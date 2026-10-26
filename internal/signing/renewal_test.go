package signing

import (
	"slices"
	"testing"
)

func TestSigningCertificateIsTheUsableOneThatExpiresLast(t *testing.T) {
	report := Report{VaultsChecked: true, Certificates: []CertificateStatus{
		{Certificate: Certificate{ID: "HELD", Type: CertificateTypeDistribution, ExpiresAt: days(200)}, Held: true},
		{Certificate: Certificate{ID: "NEWER_NOT_HELD", Type: CertificateTypeDistribution, ExpiresAt: days(300)}},
		{Certificate: Certificate{ID: "HELD_EXPIRING", Type: CertificateTypeDistribution, ExpiresAt: days(10)}, Held: true, ExpiresSoon: true},
		{Certificate: Certificate{ID: "DEV", Type: "DEVELOPMENT", ExpiresAt: days(365)}, Held: true},
	}}

	if certificate, ok := report.SigningCertificate(); !ok || certificate.ID != "HELD" {
		t.Fatalf("signing certificate = %v, %v", certificate.ID, ok)
	}
	report.VaultsChecked = false
	if certificate, ok := report.SigningCertificate(); ok {
		t.Fatalf("picked %v without reading the vaults", certificate.ID)
	}
	if _, ok := (Report{VaultsChecked: true}).SigningCertificate(); ok {
		t.Fatal("found a certificate in an empty report")
	}
}

func TestPlanRenewals(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Certificates = append(snapshot.Certificates, Certificate{ID: "NEXT", Type: CertificateTypeDistribution, ExpiresAt: days(365)})
	snapshot.BundleIDs = snapshot.BundleIDs[:1]
	snapshot.Profiles[0].ExpiresAt = days(-1)
	snapshot.Profiles[1].ExpiresAt = days(20)
	report := Evaluate(testManifest(), snapshot, policy())

	renewals, skipped, upToDate := PlanRenewals(report, "CERT")

	var got []string
	for _, renewal := range renewals {
		got = append(got, renewal.Expected.Name+": "+string(renewal.Reason)+" replacing "+renewal.Replaces.ID)
	}
	want := []string{"com.example.demo: expired replacing P1", "AdHoc com.example.demo: expiring replacing P2"}
	if removes := renewals[0].Removes; len(removes) != 1 || removes[0].ID != "P1" || len(renewals[1].Removes) != 0 {
		t.Fatalf("removes = %v / %v", removes, renewals[1].Removes)
	}
	if !slices.Equal(got, want) || upToDate != 0 || len(skipped) != 2 || skipped[0].Reason != SkipBundleIDMissing {
		t.Fatalf("renewals = %v, skipped = %v, up to date = %d", got, skipped, upToDate)
	}

	snapshot.BundleIDs = healthySnapshot().BundleIDs
	snapshot.Profiles = healthySnapshot().Profiles
	renewals, _, upToDate = PlanRenewals(Evaluate(testManifest(), snapshot, policy()), "NEXT")
	if len(renewals) != 4 || renewals[0].Reason != RenewOtherCertificate || upToDate != 0 {
		t.Fatalf("renewals for a new certificate = %v", renewals)
	}
}
