package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/damian-kolasinski/crem/internal/signing"
)

// profileState names an expected profile's most pressing issue.
func profileState(status signing.ProfileStatus) string {
	for _, candidate := range []struct {
		code  signing.FindingCode
		state string
	}{
		{signing.BundleIDMissing, "no-bundle-id"},
		{signing.ProfileMissing, "missing"},
		{signing.ProfileExpired, "expired"},
		{signing.ProfileNeedsNewCertificate, "needs-certificate"},
		{signing.ProfileExpiresSoon, "expiring"},
		{signing.ProfileBundleIDMismatch, "name-conflict"},
	} {
		if slices.Contains(status.Issues, candidate.code) {
			return candidate.state
		}
	}
	return "ok"
}

func date(at time.Time) string {
	return at.UTC().Format(time.DateOnly)
}

func renderStatus(out io.Writer, report signing.Report) error {
	var builder strings.Builder
	days := int(report.Policy.ExpiryWindow.Hours() / 24)
	fmt.Fprintf(&builder, "Team %s · checked %s · renewal window %d days · %d Ad Hoc devices\n",
		report.Team, report.Policy.Now.UTC().Format("2006-01-02 15:04 MST"), days, report.AdHocDeviceCount)

	builder.WriteString("\nDistribution certificates\n")
	table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	distribution := 0
	for _, status := range report.Certificates {
		if !status.Certificate.Type.IsDistribution() {
			continue
		}
		if distribution == 0 {
			fmt.Fprintln(table, "  ID\tNAME\tEXPIRES\tLIVE PROFILES\tNOTE")
		}
		distribution++
		note := ""
		if status.ExpiresSoon {
			note = "expiring"
		}
		fmt.Fprintf(table, "  %s\t%s\t%s\t%d\t%s\n", status.Certificate.ID, status.Certificate.Name, date(status.Certificate.ExpiresAt), status.LiveProfileCount, note)
	}
	table.Flush()
	if distribution == 0 {
		builder.WriteString("  none\n")
	}

	unhealthy := 0
	for _, status := range report.Profiles {
		if !status.Healthy() {
			unhealthy++
		}
	}
	fmt.Fprintf(&builder, "\nProfiles · %d expected, %d need action\n", len(report.Profiles), unhealthy)
	table = tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  PROFILE\tKIND\tSTATE\tEXPIRES\tNOTE")
	for _, status := range report.Profiles {
		expires, note := "", ""
		switch {
		case status.Current != nil:
			expires = date(status.Current.ExpiresAt)
		case status.LatestExpired != nil:
			expires = date(status.LatestExpired.ExpiresAt)
		}
		if status.EnabledDeviceCount != nil {
			note = fmt.Sprintf("%d of %d devices", *status.EnabledDeviceCount, report.AdHocDeviceCount)
		}
		if slices.Contains(status.Issues, signing.DuplicateLiveProfiles) {
			note = strings.TrimPrefix(note+", duplicates", ", ")
		}
		fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\n", status.Expected.Name, status.Expected.Spec.Kind, profileState(status), expires, note)
	}
	table.Flush()

	for _, severity := range []signing.Severity{signing.SeverityAction, signing.SeverityInfo} {
		groups := groupFindings(report.Findings, severity)
		if len(groups) == 0 {
			continue
		}
		if severity == signing.SeverityAction {
			builder.WriteString("\nNeeds action\n")
		} else {
			builder.WriteString("\nInfo\n")
		}
		table = tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		for _, group := range groups {
			fmt.Fprintf(table, "  %s\t%d\t%s\n", group[0].Code, len(group), summarizeFindings(group))
		}
		table.Flush()
	}

	dead := 0
	for _, candidate := range report.CleanupProfiles {
		if candidate.IsDead() {
			dead++
		}
	}
	fmt.Fprintf(&builder, "\nCleanup candidates: %s (%d dead), %s", count(len(report.CleanupProfiles), "profile"), dead, count(len(report.CleanupCertificates), "certificate"))
	if report.UntouchedProfileCount > 0 {
		fmt.Fprintf(&builder, " · %s crem never touches", count(report.UntouchedProfileCount, "other profile"))
	}
	builder.WriteString("\n")

	return writeTrimmed(out, builder.String())
}

// writeTrimmed drops the padding tabwriter leaves before empty trailing cells.
func writeTrimmed(out io.Writer, text string) error {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimRight(line, " ")
	}
	_, err := io.WriteString(out, strings.Join(lines, "\n"))
	return err
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func groupFindings(findings []signing.Finding, severity signing.Severity) [][]signing.Finding {
	var groups [][]signing.Finding
	for _, finding := range findings {
		if finding.Code.Severity() != severity {
			continue
		}
		index := slices.IndexFunc(groups, func(group []signing.Finding) bool { return group[0].Code == finding.Code })
		if index < 0 {
			groups = append(groups, []signing.Finding{finding})
		} else {
			groups[index] = append(groups[index], finding)
		}
	}
	return groups
}

func summarizeFindings(group []signing.Finding) string {
	describe := func(finding signing.Finding) string {
		if finding.Detail == "" {
			return finding.Subject
		}
		return finding.Subject + " (" + finding.Detail + ")"
	}
	const shown = 3
	var parts []string
	for _, finding := range group[:min(shown, len(group))] {
		parts = append(parts, describe(finding))
	}
	summary := strings.Join(parts, ", ")
	if len(group) > shown {
		summary += fmt.Sprintf(", and %d more", len(group)-shown)
	}
	return summary
}

type statusJSON struct {
	Team                  string            `json:"team"`
	CheckedAt             time.Time         `json:"checkedAt"`
	ExpiryWindowDays      int               `json:"expiryWindowDays"`
	AdHocDeviceCount      int               `json:"adHocDeviceCount"`
	NeedsAction           bool              `json:"needsAction"`
	Certificates          []certificateJSON `json:"certificates"`
	Profiles              []profileJSON     `json:"profiles"`
	Findings              []findingJSON     `json:"findings"`
	Cleanup               cleanupJSON       `json:"cleanup"`
	UntouchedProfileCount int               `json:"untouchedProfileCount"`
}

type certificateJSON struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	SerialNumber     string    `json:"serialNumber"`
	ExpiresAt        time.Time `json:"expiresAt"`
	LiveProfileCount int       `json:"liveProfileCount"`
	ExpiresSoon      bool      `json:"expiresSoon"`
}

type profileJSON struct {
	Name               string          `json:"name"`
	Kind               string          `json:"kind"`
	BundleID           string          `json:"bundleId"`
	App                string          `json:"app"`
	Environment        string          `json:"environment"`
	Component          string          `json:"component"`
	Secret             string          `json:"secret,omitempty"`
	BundleIDRegistered bool            `json:"bundleIdRegistered"`
	State              string          `json:"state"`
	Issues             []string        `json:"issues"`
	Current            *profileRefJSON `json:"current"`
	LatestExpired      *profileRefJSON `json:"latestExpired"`
}

type profileRefJSON struct {
	ID                 string    `json:"id"`
	ExpiresAt          time.Time `json:"expiresAt"`
	CertificateIDs     []string  `json:"certificateIds"`
	EnabledDeviceCount *int      `json:"enabledDeviceCount,omitempty"`
}

type findingJSON struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Subject  string `json:"subject"`
	Detail   string `json:"detail,omitempty"`
}

type cleanupJSON struct {
	Profiles     []cleanupProfileJSON     `json:"profiles"`
	Certificates []cleanupCertificateJSON `json:"certificates"`
}

type cleanupProfileJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	BundleID  string    `json:"bundleId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Reasons   []string  `json:"reasons"`
}

type cleanupCertificateJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func renderStatusJSON(out io.Writer, report signing.Report) error {
	document := statusJSON{
		Team:                  report.Team,
		CheckedAt:             report.Policy.Now.UTC(),
		ExpiryWindowDays:      int(report.Policy.ExpiryWindow.Hours() / 24),
		AdHocDeviceCount:      report.AdHocDeviceCount,
		NeedsAction:           report.NeedsAction(),
		Certificates:          []certificateJSON{},
		Profiles:              []profileJSON{},
		Findings:              []findingJSON{},
		Cleanup:               cleanupJSON{Profiles: []cleanupProfileJSON{}, Certificates: []cleanupCertificateJSON{}},
		UntouchedProfileCount: report.UntouchedProfileCount,
	}
	for _, status := range report.Certificates {
		certificate := status.Certificate
		document.Certificates = append(document.Certificates, certificateJSON{
			ID: certificate.ID, Name: certificate.Name, Type: string(certificate.Type), SerialNumber: certificate.SerialNumber,
			ExpiresAt: certificate.ExpiresAt.UTC(), LiveProfileCount: status.LiveProfileCount, ExpiresSoon: status.ExpiresSoon,
		})
	}
	for _, status := range report.Profiles {
		target := status.Expected.Target
		profile := profileJSON{
			Name: status.Expected.Name, Kind: status.Expected.Spec.Kind.String(), BundleID: target.BundleID,
			App: target.App, Environment: target.Environment, Component: target.Component(),
			BundleIDRegistered: status.BundleIDRegistered, State: profileState(status), Issues: []string{},
		}
		if status.Expected.Spec.Kind == signing.AppStore {
			profile.Secret = target.Secret
		}
		for _, code := range status.Issues {
			profile.Issues = append(profile.Issues, string(code))
		}
		if status.Current != nil {
			profile.Current = &profileRefJSON{ID: status.Current.ID, ExpiresAt: status.Current.ExpiresAt.UTC(), CertificateIDs: nonNil(status.Current.CertificateIDs), EnabledDeviceCount: status.EnabledDeviceCount}
		}
		if status.LatestExpired != nil {
			profile.LatestExpired = &profileRefJSON{ID: status.LatestExpired.ID, ExpiresAt: status.LatestExpired.ExpiresAt.UTC(), CertificateIDs: nonNil(status.LatestExpired.CertificateIDs)}
		}
		document.Profiles = append(document.Profiles, profile)
	}
	for _, finding := range report.Findings {
		document.Findings = append(document.Findings, findingJSON{Severity: string(finding.Code.Severity()), Code: string(finding.Code), Subject: finding.Subject, Detail: finding.Detail})
	}
	for _, candidate := range report.CleanupProfiles {
		profile := candidate.Profile
		entry := cleanupProfileJSON{ID: profile.ID, Name: profile.Name, Type: string(profile.Type), BundleID: profile.BundleID, ExpiresAt: profile.ExpiresAt.UTC(), Reasons: []string{}}
		for _, reason := range candidate.Reasons {
			entry.Reasons = append(entry.Reasons, string(reason))
		}
		document.Cleanup.Profiles = append(document.Cleanup.Profiles, entry)
	}
	for _, certificate := range report.CleanupCertificates {
		document.Cleanup.Certificates = append(document.Cleanup.Certificates, cleanupCertificateJSON{ID: certificate.ID, Name: certificate.Name, ExpiresAt: certificate.ExpiresAt.UTC()})
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
