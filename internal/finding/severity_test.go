package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.sev.String())
	}
}

func TestParseSeverity(t *testing.T) {
	sev, err := ParseSeverity("HIGH")
	require.NoError(t, err)
	assert.Equal(t, SeverityHigh, sev)

	sev, err = ParseSeverity("critical")
	require.NoError(t, err)
	assert.Equal(t, SeverityCritical, sev)

	_, err = ParseSeverity("BOGUS")
	assert.Error(t, err)
}

func TestSort(t *testing.T) {
	findings := []Finding{
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "b.yml", LineStart: 1},
		{RuleID: "NXR-GH-002", Severity: SeverityCritical, FilePath: "a.yml", LineStart: 5},
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "a.yml", LineStart: 2},
	}
	Sort(findings)
	assert.Equal(t, SeverityCritical, findings[0].Severity)
	assert.Equal(t, "a.yml", findings[1].FilePath)
}

func TestSort_StableByRuleIDAndLine(t *testing.T) {
	findings := []Finding{
		{RuleID: "NXR-GH-002", Severity: SeverityHigh, FilePath: "a.yml", LineStart: 10},
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "a.yml", LineStart: 5},
		{RuleID: "NXR-GH-001", Severity: SeverityHigh, FilePath: "a.yml", LineStart: 3},
	}
	Sort(findings)
	assert.Equal(t, "NXR-GH-001", findings[0].RuleID)
	assert.Equal(t, 3, findings[0].LineStart)
	assert.Equal(t, "NXR-GH-001", findings[1].RuleID)
	assert.Equal(t, 5, findings[1].LineStart)
	assert.Equal(t, "NXR-GH-002", findings[2].RuleID)
}

func TestFilter_Threshold(t *testing.T) {
	findings := []Finding{
		{RuleID: "A", Severity: SeverityInfo},
		{RuleID: "B", Severity: SeverityLow},
		{RuleID: "C", Severity: SeverityMedium},
		{RuleID: "D", Severity: SeverityHigh},
		{RuleID: "E", Severity: SeverityCritical},
	}

	got := Filter(findings, SeverityHigh)
	assert.Len(t, got, 2)
	assert.Equal(t, "D", got[0].RuleID)
	assert.Equal(t, "E", got[1].RuleID)
}

func TestFilter_InfoThreshold_ReturnsAll(t *testing.T) {
	findings := []Finding{
		{RuleID: "A", Severity: SeverityInfo},
		{RuleID: "B", Severity: SeverityCritical},
	}
	got := Filter(findings, SeverityInfo)
	assert.Len(t, got, 2)
}

func TestFilter_Empty(t *testing.T) {
	got := Filter(nil, SeverityHigh)
	assert.Empty(t, got)
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	f1 := Finding{
		RuleID:   "NXR-GH-001",
		FilePath: "path/to/file.yml",
		Evidence: "permissions: write-all",
	}
	f2 := f1
	f1.ComputeFingerprint()
	f2.ComputeFingerprint()
	assert.Equal(t, f1.Fingerprint, f2.Fingerprint)
	assert.NotEmpty(t, f1.Fingerprint)
}

func TestComputeFingerprint_DifferentRules_DifferentFingerprints(t *testing.T) {
	f1 := Finding{RuleID: "NXR-GH-001", FilePath: "a.yml", Evidence: "x"}
	f2 := Finding{RuleID: "NXR-GH-002", FilePath: "a.yml", Evidence: "x"}
	f1.ComputeFingerprint()
	f2.ComputeFingerprint()
	assert.NotEqual(t, f1.Fingerprint, f2.Fingerprint)
}

func TestSeverityString_Unknown(t *testing.T) {
	s := Severity(99)
	assert.Equal(t, "UNKNOWN", s.String())
}

func TestParseSeverity_AllValues(t *testing.T) {
	cases := map[string]Severity{
		"info":     SeverityInfo,
		"low":      SeverityLow,
		"medium":   SeverityMedium,
		"high":     SeverityHigh,
		"critical": SeverityCritical,
	}
	for input, want := range cases {
		got, err := ParseSeverity(input)
		require.NoError(t, err)
		assert.Equal(t, want, got, "input: %s", input)
	}
}
