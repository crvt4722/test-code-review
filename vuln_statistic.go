package repo

import (
	"code.gitea.io/gitea/models/db"
	"context"
	"time"
)

type VulnStatistic struct {
	ID           int64     `xorm:"pk autoincr"`
	RepoID       int64     `xorm:"INDEX"`
	ScanType     string    `xorm:"VARCHAR(255)"`
	VulnQuantity int64     `xorm:"INT"`
	Date         time.Time `xorm:"DATE"`
}

func init() {
	db.RegisterModel(new(VulnStatistic))
}
func UpdateVulnScanStatistic(ctx context.Context, repoID int64, scanType string, vulnQuantity int64) error {

	currentDate := time.Now().UTC().Truncate(24 * time.Hour)

	var existingStat VulnStatistic
	has, err := db.GetEngine(ctx).Where("repo_id = ? AND scan_type = ? AND date = ?", repoID, scanType, currentDate).Get(&existingStat)
	if err != nil {
		return err
	}

	if has {
		existingStat.VulnQuantity = vulnQuantity
		_, err = db.GetEngine(ctx).ID(existingStat.ID).Update(&existingStat)
		if err != nil {
			return err
		}
	} else {
		newStat := VulnStatistic{
			RepoID:       repoID,
			ScanType:     scanType,
			VulnQuantity: vulnQuantity,
			Date:         currentDate,
		}
		_, err = db.GetEngine(ctx).Insert(&newStat)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetVulnScanStatisticsLast12Days(ctx context.Context, repoID int64) (map[string][]int64, error) {
	startDate := time.Now().UTC().AddDate(0, 0, -12).Truncate(24 * time.Hour)

	var stats []VulnStatistic
	err := db.GetEngine(ctx).Where("repo_id = ? AND date >= ?", repoID, startDate).Find(&stats)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]int64)

	scanTypes := []string{"dependency_vuln", "iac_misconfig", "secret_detection"}
	for _, scanType := range scanTypes {
		result[scanType] = make([]int64, 12)
	}

	for _, stat := range stats {
		daysAgo := int(time.Now().UTC().Sub(stat.Date).Hours() / 24)
		if daysAgo >= 0 && daysAgo < 12 {
			result[stat.ScanType][11-daysAgo] += stat.VulnQuantity
		}
	}

	return result, nil
}

func GetVulnScanStatisticsLast12Weeks(ctx context.Context, repoID int64) (map[string][]int64, error) {
	startDate := time.Now().UTC().AddDate(0, 0, -7*12).Truncate(24 * time.Hour)
	startDate = startDate.AddDate(0, 0, -int(startDate.Weekday())+1)

	var stats []VulnStatistic
	err := db.GetEngine(ctx).Where("repo_id = ? AND date >= ?", repoID, startDate).Find(&stats)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]int64)
	scanTypes := []string{"dependency_vuln", "iac_misconfig", "secret_detection"}
	for _, scanType := range scanTypes {
		result[scanType] = make([]int64, 12)
	}
	now := time.Now().UTC()
	for _, stat := range stats {
		mondayOfWeek := stat.Date.AddDate(0, 0, -int(stat.Date.Weekday())+1)
		weeksAgo := int(now.Sub(mondayOfWeek).Hours() / (24 * 7))

		if weeksAgo >= 0 && weeksAgo < 12 {
			result[stat.ScanType][11-weeksAgo] += stat.VulnQuantity
		}
	}

	return result, nil
}

func GetVulnScanStatisticsLast12Months(ctx context.Context, repoID int64) (map[string][]int64, error) {
	startDate := time.Now().UTC().AddDate(0, -12, 0).Truncate(24 * time.Hour)
	startDate = time.Date(startDate.Year(), startDate.Month(), 1, 0, 0, 0, 0, time.UTC)
	var stats []VulnStatistic
	err := db.GetEngine(ctx).Where("repo_id = ? AND date >= ?", repoID, startDate).Find(&stats)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]int64)
	scanTypes := []string{"dependency_vuln", "iac_misconfig", "secret_detection"}
	for _, scanType := range scanTypes {
		result[scanType] = make([]int64, 12)
	}

	now := time.Now().UTC()
	for _, stat := range stats {
		monthStart := time.Date(stat.Date.Year(), stat.Date.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthsAgo := (now.Year()-monthStart.Year())*12 + int(now.Month()-monthStart.Month())

		if monthsAgo >= 0 && monthsAgo < 12 {
			result[stat.ScanType][11-monthsAgo] += stat.VulnQuantity
		}
	}

	return result, nil
}
