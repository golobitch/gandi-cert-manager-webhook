package main

import (
	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"os"
	"testing"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.
	//

	// Uncomment the below fixture when implementing your custom DNS provider
	solver := &gandiDNSProviderSolver{}
	fixture := acmetest.NewFixture(solver,
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/gandi"),
		//acmetest.SetBinariesPath("_test/kubebuilder/bin"),
	)

	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
