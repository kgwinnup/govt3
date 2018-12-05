package virustotal

import "strings"
import "io/ioutil"
import "os"
import "testing"

func vtobject() *VirusTotal {
	buf, _ := ioutil.ReadFile(os.Getenv("HOME") + "/vt.token")
	return New(strings.TrimSuffix(string(buf), "\n"))
}

func ATestGetUser(t *testing.T) {
	vt := vtobject()
	if _, err := vt.GetUser(""); err != nil {
		t.Error(err)
	}

}

func ATestGetGroup(t *testing.T) {
	vt := vtobject()
	if _, err := vt.GetGroup(""); err != nil {
		t.Error(err)
	}
}

func ATestGetHuntingRulesets(t *testing.T) {
	vt := vtobject()
	if _, err := vt.GetHuntingRulesets(); err != nil {
		t.Error(err)
	}
}

func TestHashAnalysis(t *testing.T) {
	vt := vtobject()
	if _, err := vt.GetHashAnalysis("d917dd47406322341cef40cf38091292962ba81d42983456aae4dc4f7967afb1"); err != nil {
		t.Error(err)
	}
}
