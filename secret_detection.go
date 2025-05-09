package repo

import (
	"context"
	"slices"
	"strings"
	"xorm.io/builder"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

type RepoSecretDetections []*RepoSecretDetection

type RepoSecretDetection struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"INDEX"`
	BranchName  string             `xorm:"VARCHAR(255)"`
	RuleID      string             `xorm:"VARCHAR(255)"`
	Target      string             `xorm:"VARCHAR(255)"`
	Category    string             `xorm:"VARCHAR(255)"`
	Severity    string             `xorm:"VARCHAR(100)"`
	Title       string             `xorm:"TEXT"`
	CodeContent string             `xorm:"TEXT"`
	LastScanned timeutil.TimeStamp `xorm:"INDEX last_scanned"`
}

type RepoSecretDetectionSearchOptions struct {
	db.ListOptions
	RepoSecretDetection
	Q string
}

// Register the model with the database
func init() {
	db.RegisterModel(new(RepoSecretDetection))
}

func (opts RepoSecretDetectionSearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_secret_detection.repo_id": opts.RepoID})
	}
	if opts.Target != "" {
		cond = cond.And(builder.Eq{"repo_secret_detection.target": opts.Target})
	}
	if opts.Severity != "" {
		cond = cond.And(builder.Eq{"repo_secret_detection.severity": opts.Severity})
	}
	if opts.BranchName != "" {
		cond = cond.And(builder.Eq{"repo_secret_detection.branch_name": opts.BranchName})
	}
	if opts.Q != "" {
		cond = cond.And(builder.Like{"LOWER(repo_secret_detection.title)", opts.Q})
	}
	return cond
}

// GetRepoSecretDetection retrieves a secret vulnerability by its ID
func GetRepoSecretDetection(ctx context.Context, ID int64) (*RepoSecretDetection, error) {
	var secretVuln RepoSecretDetection
	exists, err := db.GetEngine(ctx).Where("id = ?", ID).Get(&secretVuln)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &secretVuln, nil
}

// GetExistRepoSecretDetection retrieves an existing secret vulnerability.
func GetExistRepoSecretDetection(ctx context.Context, repoID int64, category, target, codeContent, branchName string) (*RepoSecretDetection, error) {
	var secretVuln RepoSecretDetection
	exists, err := db.GetEngine(ctx).Where("category = ?", category).And("repo_id = ?", repoID).And("target = ?", target).And("branch_name = ?", branchName).And("code_content = ?", codeContent).Get(&secretVuln)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &secretVuln, nil
}

// ListSecretDetections retrieves all secret vulnerabilities for a repository
func ListRepoSecretDetections(ctx context.Context, repoID int64, filter map[string]string) (RepoSecretDetections, error) {
	opts := RepoSecretDetectionSearchOptions{
		RepoSecretDetection: RepoSecretDetection{
			RepoID:     repoID,
			Target:     "",
			Severity:   "",
			BranchName: "",
		},
		ListOptions: db.ListOptions{
			ListAll: true,
		},
		Q: "",
	}
	if filter != nil {
		if filter["q"] != "" {
			opts.Q = "%" + strings.ToLower(filter["q"]) + "%"
		}
		if filter["location"] != "" {
			opts.Target = filter["location"]
		}
		if filter["severity"] != "" {
			opts.Severity = filter["severity"]
		}
		if filter["branch_name"] != "" {
			opts.BranchName = filter["branch_name"]
		}
	}

	secretVulns, _, err := db.FindAndCount[RepoSecretDetection](ctx, opts)
	if err != nil {
		return nil, err
	}
	return secretVulns, nil
}

func GetListSecretDetectionFilter(ctx context.Context, repoID int64) map[string][]string {
	res := map[string][]string{
		"location":    {},
		"severity":    {},
		"branch_name": {},
	}
	results := RepoSecretDetections{}
	if err := db.GetEngine(ctx).Distinct("target", "severity", "branch_name").Where("repo_id = ?", repoID).Find(&results); err == nil {
		for _, bean := range results {
			if !slices.Contains(res["location"], bean.Target) {
				res["location"] = append(res["location"], bean.Target)
			}
			if !slices.Contains(res["severity"], bean.Severity) {
				res["severity"] = append(res["severity"], bean.Severity)
			}
			if !slices.Contains(res["branch_name"], bean.BranchName) {
				res["branch_name"] = append(res["branch_name"], bean.BranchName)
			}
		}
	}
	return res
}

// CreateOrUpdateRepoSecretDetection creates a secret vulnerability or updates an existing one
func CreateOrUpdateRepoSecretDetection(ctx context.Context, repoID int64, ruleID, target, category, serverity, title,
	branchName, codeContent string, lastScanned timeutil.TimeStamp) (*RepoSecretDetection, error) {
	// Check if the misconfiguration already exists
	existingSecretVuln, err := GetExistRepoSecretDetection(ctx, repoID, category, target, codeContent, branchName)
	if err != nil {
		return nil, err
	}

	if existingSecretVuln == nil {
		// Create a new misconfiguration
		secretVuln := &RepoSecretDetection{
			RuleID:      ruleID,
			RepoID:      repoID,
			BranchName:  branchName,
			Category:    category,
			Target:      target,
			Severity:    serverity,
			Title:       title,
			CodeContent: codeContent,
			LastScanned: lastScanned,
		}
		// Insert the new misconfiguration into the database
		if err := db.Insert(ctx, secretVuln); err != nil {
			return nil, err
		}
		return secretVuln, nil
	} else {
		// Update the existing misconfiguration
		existingSecretVuln.LastScanned = lastScanned
		if _, err := db.GetEngine(ctx).ID(existingSecretVuln.ID).Cols("last_scanned").Update(existingSecretVuln); err != nil {
			return nil, err
		}
		return existingSecretVuln, nil
	}
}

func GetTotalSecretDetecttion(ctx context.Context, repoID int64) (int64, error) {
	repo, err := GetRepositoryByID(ctx, repoID)
	if err != nil {
		return 0, err
	}
	total, err := db.GetEngine(ctx).
		Where("repo_id = ?", repoID).
		And("branch_name = ?", repo.DefaultBranch).
		Count(&RepoSecretDetection{})
	if err != nil {
		return 0, err
	}
	return total, nil
}
