// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package slsa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

var containerAnalysisResponse = []byte(`
{
  "occurrences": [
    {
      "name": "projects/imre-test/occurrences/3af2d63d-518a-40af-b39c-fc2a7f75bfee",
      "resourceUri": "https://us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529",
      "noteName": "projects/verified-builder/notes/1dbbe813-4f3d-4c8e-b2d3-776c91481bb8",
      "kind": "BUILD",
      "createTime": "2023-02-17T09:56:57.174925Z",
      "updateTime": "2023-02-17T09:56:57.174925Z",
      "build": {
        "provenance": {
          "id": "1dbbe813-4f3d-4c8e-b2d3-776c91481bb8",
          "projectId": "imre-test",
          "commands": [
            {
              "name": "gcr.io/cloud-builders/docker",
              "args": [
                "build",
                "-t",
                "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:v41",
                "."
              ]
            }
          ],
          "builtArtifacts": [
            {
              "checksum": "sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529",
              "id": "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529",
              "names": [
                "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:v41"
              ]
            }
          ],
          "createTime": "2023-02-17T09:56:40.446566Z",
          "startTime": "2023-02-17T09:56:41.000101282Z",
          "endTime": "2023-02-17T09:56:56.113063Z",
          "creator": "79219187776@cloudbuild.gserviceaccount.com",
          "logsUri": "gs://79219187776.cloudbuild-logs.googleusercontent.com",
          "sourceProvenance": {
            "context": {
              "git": {
                "url": "https://github.com/irsl/gcb-tests/commit/6da093fbd4f14b31e6895154d070fb0113bc3aa8",
                "revisionId": "6da093fbd4f14b31e6895154d070fb0113bc3aa8"
              }
            }
          },
          "triggerId": "714d3c68-b4fd-4d8e-ad80-f1ac66d6c4f0",
          "buildOptions": {
            "VerifyOption": "VERIFIED"
          },
          "builderVersion": "508019100"
        },
        "provenanceBytes": "eyJpZCI6IjFkYmJlODEzLTRmM2QtNGM4ZS1iMmQzLTc3NmM5MTQ4MWJiOCIsInByb2plY3RJZCI6ImltcmUtdGVzdCIsImNvbW1hbmRzIjpbeyJuYW1lIjoiZ2NyLmlvL2Nsb3VkLWJ1aWxkZXJzL2RvY2tlciIsImFyZ3MiOlsiYnVpbGQiLCItdCIsInVzLXdlc3QyLWRvY2tlci5wa2cuZGV2L2ltcmUtdGVzdC9xdWlja3N0YXJ0LWRvY2tlci1yZXBvL3F1aWNrc3RhcnQtaW1hZ2U6djQxIiwiLiJdfV0sImJ1aWx0QXJ0aWZhY3RzIjpbeyJjaGVja3N1bSI6InNoYTI1Njo0MWNiNGI1ZTMyZTQxN2I4NmMyYjIyMjlkMDU4MWI3MmY3ZGZmZDFjYzZiMGU1ODZhYjJjZWZkYjdhNTI3NTI5IiwiaWQiOiJ1cy13ZXN0Mi1kb2NrZXIucGtnLmRldi9pbXJlLXRlc3QvcXVpY2tzdGFydC1kb2NrZXItcmVwby9xdWlja3N0YXJ0LWltYWdlQHNoYTI1Njo0MWNiNGI1ZTMyZTQxN2I4NmMyYjIyMjlkMDU4MWI3MmY3ZGZmZDFjYzZiMGU1ODZhYjJjZWZkYjdhNTI3NTI5IiwibmFtZXMiOlsidXMtd2VzdDItZG9ja2VyLnBrZy5kZXYvaW1yZS10ZXN0L3F1aWNrc3RhcnQtZG9ja2VyLXJlcG8vcXVpY2tzdGFydC1pbWFnZTp2NDEiXX1dLCJjcmVhdGVUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo0MC40NDY1NjZaIiwic3RhcnRUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo0MS4wMDAxMDEyODJaIiwiZW5kVGltZSI6IjIwMjMtMDItMTdUMDk6NTY6NTYuMTEzMDYzWiIsImNyZWF0b3IiOiI3OTIxOTE4Nzc3NkBjbG91ZGJ1aWxkLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJsb2dzVXJpIjoiZ3M6Ly83OTIxOTE4Nzc3Ni5jbG91ZGJ1aWxkLWxvZ3MuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic291cmNlUHJvdmVuYW5jZSI6eyJjb250ZXh0Ijp7ImdpdCI6eyJ1cmwiOiJodHRwczovL2dpdGh1Yi5jb20vaXJzbC9nY2ItdGVzdHMvY29tbWl0LzZkYTA5M2ZiZDRmMTRiMzFlNjg5NTE1NGQwNzBmYjAxMTNiYzNhYTgiLCJyZXZpc2lvbklkIjoiNmRhMDkzZmJkNGYxNGIzMWU2ODk1MTU0ZDA3MGZiMDExM2JjM2FhOCJ9fX0sInRyaWdnZXJJZCI6IjcxNGQzYzY4LWI0ZmQtNGQ4ZS1hZDgwLWYxYWM2NmQ2YzRmMCIsImJ1aWxkT3B0aW9ucyI6eyJWZXJpZnlPcHRpb24iOiJWRVJJRklFRCJ9LCJidWlsZGVyVmVyc2lvbiI6IjUwODAxOTEwMCJ9"
      }
    },
    {
      "name": "projects/imre-test/occurrences/42b57797-96c2-4031-95ac-f67250fa6d28",
      "resourceUri": "https://us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529",
      "noteName": "projects/verified-builder/notes/intoto_1dbbe813-4f3d-4c8e-b2d3-776c91481bb8",
      "kind": "BUILD",
      "createTime": "2023-02-17T09:56:58.259006Z",
      "updateTime": "2023-02-17T09:56:58.259006Z",
      "envelope": {
        "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZSI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9jbG91ZGJ1aWxkLmdvb2dsZWFwaXMuY29tL0dvb2dsZUhvc3RlZFdvcmtlckB2MC4zIn0sIm1hdGVyaWFscyI6W3siZGlnZXN0Ijp7InNoYTEiOiI2ZGEwOTNmYmQ0ZjE0YjMxZTY4OTUxNTRkMDcwZmIwMTEzYmMzYWE4In0sInVyaSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9pcnNsL2djYi10ZXN0cyJ9XSwibWV0YWRhdGEiOnsiYnVpbGRGaW5pc2hlZE9uIjoiMjAyMy0wMi0xN1QwOTo1Njo1Ni4xMTMwNjNaIiwiYnVpbGRJbnZvY2F0aW9uSWQiOiIxZGJiZTgxMy00ZjNkLTRjOGUtYjJkMy03NzZjOTE0ODFiYjgiLCJidWlsZFN0YXJ0ZWRPbiI6IjIwMjMtMDItMTdUMDk6NTY6NDEuMDAwMTAxMjgyWiJ9LCJyZWNpcGUiOnsiYXJndW1lbnRzIjp7IkB0eXBlIjoidHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuZGV2dG9vbHMuY2xvdWRidWlsZC52MS5CdWlsZCIsImlkIjoiMWRiYmU4MTMtNGYzZC00YzhlLWIyZDMtNzc2YzkxNDgxYmI4IiwibmFtZSI6InByb2plY3RzLzc5MjE5MTg3Nzc2L2xvY2F0aW9ucy91cy13ZXN0Mi9idWlsZHMvMWRiYmU4MTMtNGYzZC00YzhlLWIyZDMtNzc2YzkxNDgxYmI4Iiwib3B0aW9ucyI6eyJkeW5hbWljU3Vic3RpdHV0aW9ucyI6dHJ1ZSwibG9nZ2luZyI6IkxFR0FDWSIsInBvb2wiOnt9LCJyZXF1ZXN0ZWRWZXJpZnlPcHRpb24iOiJWRVJJRklFRCIsInN1YnN0aXR1dGlvbk9wdGlvbiI6IkFMTE9XX0xPT1NFIn0sInNvdXJjZVByb3ZlbmFuY2UiOnt9LCJzdGVwcyI6W3siYXJncyI6WyJidWlsZCIsIi10IiwidXMtd2VzdDItZG9ja2VyLnBrZy5kZXYvaW1yZS10ZXN0L3F1aWNrc3RhcnQtZG9ja2VyLXJlcG8vcXVpY2tzdGFydC1pbWFnZTp2NDEiLCIuIl0sIm5hbWUiOiJnY3IuaW8vY2xvdWQtYnVpbGRlcnMvZG9ja2VyIiwicHVsbFRpbWluZyI6eyJlbmRUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo0NC4zMjQ3NDU0ODlaIiwic3RhcnRUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo0NC4zMjA2NjE3MThaIn0sInN0YXR1cyI6IlNVQ0NFU1MiLCJ0aW1pbmciOnsiZW5kVGltZSI6IjIwMjMtMDItMTdUMDk6NTY6NTAuNTk4NTA4NzU4WiIsInN0YXJ0VGltZSI6IjIwMjMtMDItMTdUMDk6NTY6NDQuMzIwNjYxNzE4WiJ9fV0sInN1YnN0aXR1dGlvbnMiOnsiQlJBTkNIX05BTUUiOiJtYWluIiwiQ09NTUlUX1NIQSI6IjZkYTA5M2ZiZDRmMTRiMzFlNjg5NTE1NGQwNzBmYjAxMTNiYzNhYTgiLCJSRUZfTkFNRSI6Im1haW4iLCJSRVBPX05BTUUiOiJnY2ItdGVzdHMiLCJSRVZJU0lPTl9JRCI6IjZkYTA5M2ZiZDRmMTRiMzFlNjg5NTE1NGQwNzBmYjAxMTNiYzNhYTgiLCJTSE9SVF9TSEEiOiI2ZGEwOTNmIiwiVFJJR0dFUl9CVUlMRF9DT05GSUdfUEFUSCI6ImNsb3VkYnVpbGQueWFtbCIsIlRSSUdHRVJfTkFNRSI6InRyaWdnZXIifX0sImVudHJ5UG9pbnQiOiJjbG91ZGJ1aWxkLnlhbWwiLCJ0eXBlIjoiaHR0cHM6Ly9jbG91ZGJ1aWxkLmdvb2dsZWFwaXMuY29tL0Nsb3VkQnVpbGRZYW1sQHYwLjEifX0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMSIsInNsc2FQcm92ZW5hbmNlIjp7ImJ1aWxkZXIiOnsiaWQiOiJodHRwczovL2Nsb3VkYnVpbGQuZ29vZ2xlYXBpcy5jb20vR29vZ2xlSG9zdGVkV29ya2VyQHYwLjMifSwibWF0ZXJpYWxzIjpbeyJkaWdlc3QiOnsic2hhMSI6IjZkYTA5M2ZiZDRmMTRiMzFlNjg5NTE1NGQwNzBmYjAxMTNiYzNhYTgifSwidXJpIjoiaHR0cHM6Ly9naXRodWIuY29tL2lyc2wvZ2NiLXRlc3RzIn1dLCJtZXRhZGF0YSI6eyJidWlsZEZpbmlzaGVkT24iOiIyMDIzLTAyLTE3VDA5OjU2OjU2LjExMzA2M1oiLCJidWlsZEludm9jYXRpb25JZCI6IjFkYmJlODEzLTRmM2QtNGM4ZS1iMmQzLTc3NmM5MTQ4MWJiOCIsImJ1aWxkU3RhcnRlZE9uIjoiMjAyMy0wMi0xN1QwOTo1Njo0MS4wMDAxMDEyODJaIn0sInJlY2lwZSI6eyJhcmd1bWVudHMiOnsiQHR5cGUiOiJ0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5kZXZ0b29scy5jbG91ZGJ1aWxkLnYxLkJ1aWxkIiwiaWQiOiIxZGJiZTgxMy00ZjNkLTRjOGUtYjJkMy03NzZjOTE0ODFiYjgiLCJuYW1lIjoicHJvamVjdHMvNzkyMTkxODc3NzYvbG9jYXRpb25zL3VzLXdlc3QyL2J1aWxkcy8xZGJiZTgxMy00ZjNkLTRjOGUtYjJkMy03NzZjOTE0ODFiYjgiLCJvcHRpb25zIjp7ImR5bmFtaWNTdWJzdGl0dXRpb25zIjp0cnVlLCJsb2dnaW5nIjoiTEVHQUNZIiwicG9vbCI6e30sInJlcXVlc3RlZFZlcmlmeU9wdGlvbiI6IlZFUklGSUVEIiwic3Vic3RpdHV0aW9uT3B0aW9uIjoiQUxMT1dfTE9PU0UifSwic291cmNlUHJvdmVuYW5jZSI6e30sInN0ZXBzIjpbeyJhcmdzIjpbImJ1aWxkIiwiLXQiLCJ1cy13ZXN0Mi1kb2NrZXIucGtnLmRldi9pbXJlLXRlc3QvcXVpY2tzdGFydC1kb2NrZXItcmVwby9xdWlja3N0YXJ0LWltYWdlOnY0MSIsIi4iXSwibmFtZSI6Imdjci5pby9jbG91ZC1idWlsZGVycy9kb2NrZXIiLCJwdWxsVGltaW5nIjp7ImVuZFRpbWUiOiIyMDIzLTAyLTE3VDA5OjU2OjQ0LjMyNDc0NTQ4OVoiLCJzdGFydFRpbWUiOiIyMDIzLTAyLTE3VDA5OjU2OjQ0LjMyMDY2MTcxOFoifSwic3RhdHVzIjoiU1VDQ0VTUyIsInRpbWluZyI6eyJlbmRUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo1MC41OTg1MDg3NThaIiwic3RhcnRUaW1lIjoiMjAyMy0wMi0xN1QwOTo1Njo0NC4zMjA2NjE3MThaIn19XSwic3Vic3RpdHV0aW9ucyI6eyJCUkFOQ0hfTkFNRSI6Im1haW4iLCJDT01NSVRfU0hBIjoiNmRhMDkzZmJkNGYxNGIzMWU2ODk1MTU0ZDA3MGZiMDExM2JjM2FhOCIsIlJFRl9OQU1FIjoibWFpbiIsIlJFUE9fTkFNRSI6ImdjYi10ZXN0cyIsIlJFVklTSU9OX0lEIjoiNmRhMDkzZmJkNGYxNGIzMWU2ODk1MTU0ZDA3MGZiMDExM2JjM2FhOCIsIlNIT1JUX1NIQSI6IjZkYTA5M2YiLCJUUklHR0VSX0JVSUxEX0NPTkZJR19QQVRIIjoiY2xvdWRidWlsZC55YW1sIiwiVFJJR0dFUl9OQU1FIjoidHJpZ2dlciJ9fSwiZW50cnlQb2ludCI6ImNsb3VkYnVpbGQueWFtbCIsInR5cGUiOiJodHRwczovL2Nsb3VkYnVpbGQuZ29vZ2xlYXBpcy5jb20vQ2xvdWRCdWlsZFlhbWxAdjAuMSJ9fSwic3ViamVjdCI6W3siZGlnZXN0Ijp7InNoYTI1NiI6IjQxY2I0YjVlMzJlNDE3Yjg2YzJiMjIyOWQwNTgxYjcyZjdkZmZkMWNjNmIwZTU4NmFiMmNlZmRiN2E1Mjc1MjkifSwibmFtZSI6Imh0dHBzOi8vdXMtd2VzdDItZG9ja2VyLnBrZy5kZXYvaW1yZS10ZXN0L3F1aWNrc3RhcnQtZG9ja2VyLXJlcG8vcXVpY2tzdGFydC1pbWFnZTp2NDEifV19",
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [
          {
            "sig": "MEUCIQCi3Nul7fQCdJBFzWTOl+nnsBuhfx26Wc8LDeWDuxxAewIgV4TsY0iEMgU/JXf+RuhHTVT6u3TbvhMdYtIzVhHxw/w=",
            "keyid": "projects/verified-builder/locations/us-west2/keyRings/attestor/cryptoKeys/builtByGCB/cryptoKeyVersions/1"
          }
        ]
      },
      "build": {
        "intotoStatement": {
          "_type": "https://in-toto.io/Statement/v0.1",
          "subject": [
            {
              "name": "https://us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:v41",
              "digest": {
                "sha256": "41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529"
              }
            }
          ],
          "predicateType": "https://slsa.dev/provenance/v0.1",
          "slsaProvenance": {
            "builder": {
              "id": "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3"
            },
            "recipe": {
              "type": "https://cloudbuild.googleapis.com/CloudBuildYaml@v0.1",
              "entryPoint": "cloudbuild.yaml",
              "arguments": {
                "@type": "type.googleapis.com/google.devtools.cloudbuild.v1.Build",
                "id": "1dbbe813-4f3d-4c8e-b2d3-776c91481bb8",
                "steps": [
                  {
                    "name": "gcr.io/cloud-builders/docker",
                    "args": [
                      "build",
                      "-t",
                      "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:v41",
                      "."
                    ],
                    "timing": {
                      "startTime": "2023-02-17T09:56:44.320661718Z",
                      "endTime": "2023-02-17T09:56:50.598508758Z"
                    },
                    "status": "SUCCESS",
                    "pullTiming": {
                      "startTime": "2023-02-17T09:56:44.320661718Z",
                      "endTime": "2023-02-17T09:56:44.324745489Z"
                    }
                  }
                ],
                "sourceProvenance": {},
                "options": {
                  "requestedVerifyOption": "VERIFIED",
                  "substitutionOption": "ALLOW_LOOSE",
                  "logging": "LEGACY",
                  "dynamicSubstitutions": true,
                  "pool": {}
                },
                "substitutions": {
                  "COMMIT_SHA": "6da093fbd4f14b31e6895154d070fb0113bc3aa8",
                  "SHORT_SHA": "6da093f",
                  "BRANCH_NAME": "main",
                  "REF_NAME": "main",
                  "TRIGGER_NAME": "trigger",
                  "TRIGGER_BUILD_CONFIG_PATH": "cloudbuild.yaml",
                  "REPO_NAME": "gcb-tests",
                  "REVISION_ID": "6da093fbd4f14b31e6895154d070fb0113bc3aa8"
                },
                "name": "projects/79219187776/locations/us-west2/builds/1dbbe813-4f3d-4c8e-b2d3-776c91481bb8"
              }
            },
            "metadata": {
              "buildInvocationId": "1dbbe813-4f3d-4c8e-b2d3-776c91481bb8",
              "buildStartedOn": "2023-02-17T09:56:41.000101282Z",
              "buildFinishedOn": "2023-02-17T09:56:56.113063Z"
            },
            "materials": [
              {
                "uri": "https://github.com/irsl/gcb-tests",
                "digest": {
                  "sha1": "6da093fbd4f14b31e6895154d070fb0113bc3aa8"
                }
              }
            ]
          }
        }
      }
    }
  ]
}
`)

func TestExtractGcpProjectFromImageRef(t *testing.T) {
	testCases := map[string]string{
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529": "imre-test",
	}
	for input, want := range testCases {
		got := extractGcpProjectFromImageRef(input)
		if got != want {
			t.Errorf("extractGcpProjectFromImageRef(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGetImageHash(t *testing.T) {
	testCases := map[string]string{
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529": "sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529",
		"us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:sometag":                                                                         "",
	}
	for input, want := range testCases {
		got := getImageHash(input)
		if got != want {
			t.Errorf("getImageHash(%q) = %q, want %q", input, got, want)
		}
	}
}

type mockedHTTPDoer struct {
	expectedAuthorizationHeader string
	expectedURL                 string
}

func (m mockedHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() != m.expectedURL {
		return nil, fmt.Errorf("unexpected URL: %v vs %v", req.URL, m.expectedURL)
	}
	if req.Header.Get("Authorization") != m.expectedAuthorizationHeader {
		return nil, fmt.Errorf("unexpected authorization: %v vs %v", req.Header.Get("Authorization"), m.expectedAuthorizationHeader)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(containerAnalysisResponse)),
	}, nil
}

func TestObtainGoogleCloudProvenance(t *testing.T) {
	origGetGoogleAccessToken := getGoogleAccessToken
	defer func() { getGoogleAccessToken = origGetGoogleAccessToken }()
	getGoogleAccessToken = func() (string, error) { return "specialtoken", nil }

	origGetHTTPDoer := getHTTPDoer
	defer func() { getHTTPDoer = origGetHTTPDoer }()
	myMockedHTTPDoer := mockedHTTPDoer{
		expectedAuthorizationHeader: "Bearer specialtoken",
		// note, the :v41 tag is stripped!
		expectedURL: "https://containeranalysis.googleapis.com/v1/projects/imre-test/occurrences?alt=json&filter=%28%28kind+%3D+%22BUILD%22%29+OR+%28kind+%3D+%22DSSE_ATTESTATION%22%29%29+AND+%28resourceUrl+%3D+%22https%3A%2F%2Fus-west2-docker.pkg.dev%2Fimre-test%2Fquickstart-docker-repo%2Fquickstart-image%40sha256%3A41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529%22%29&pageSize=10",
	}
	getHTTPDoer = func() httpDoer { return myMockedHTTPDoer }

	provBytes, err := ObtainGoogleCloudProvenance("us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image:v41@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529")
	if err != nil {
		t.Fatal(err)
	}

	var gp GcpProvenance
	err = json.Unmarshal(provBytes, &gp)
	if err != nil {
		t.Fatal(err)
	}
	expectedRebuiltFullyQualified := "us-west2-docker.pkg.dev/imre-test/quickstart-docker-repo/quickstart-image@sha256:41cb4b5e32e417b86c2b2229d0581b72f7dffd1cc6b0e586ab2cefdb7a527529"
	if gp.ImageSummary.FullyQualifiedDigest != expectedRebuiltFullyQualified {
		t.Errorf("sanity check on GcpProvenance failed: %v vs %v", gp.ImageSummary.FullyQualifiedDigest, expectedRebuiltFullyQualified)
	}
}
