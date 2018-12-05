package virustotal

import "fmt"
import "bytes"
import "net/http"
import "io/ioutil"
import "encoding/json"

type VtError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type VirusTotal struct {
	Apikey  string
	baseurl string
}

type UserPrivileges struct {
	Granted       bool   `json:"granted"`
	InheritedFrom string `json:"inherited_from"`
}

type Quota struct {
	Allowed int `json:"allowed"`
	Used    int `json:"used"`
}

type Quotas struct {
	ApiRequestsDaily                 Quota `json:"api_requests_daily"`
	ApiRequestsHourly                Quota `json:"api_requests_hourly"`
	ApiRequestsMonthly               Quota `json:"api_requests_monthly"`
	IntelligenceDownloadsMonthly     Quota `json:"intelligence_downloads_monthly"`
	IntelligenceGraphsPrivate        Quota `json:"intelligence_graphs_private"`
	IntelligenceHuntingRules         Quota `json:"intelligence_hunting_rules"`
	IntelligenceRetrohuntJobsMonthly Quota `json:"intelligence_retrohunt_jobs_monthly"`
	IntelligenceSearchesMonthly      Quota `json:"intelligence_searches_monthly"`
	MonitorStorageBytes              Quota `json:"monitor_storage_bytes"`
	MonitorStorageFiles              Quota `json:"monitor_storage_files"`
	MonitorUploadedBytes             Quota `json:"monitor_uploaded_bytes"`
	MonitorUploadedFiles             Quota `json:"monitor_uploaded_files"`
}

type GroupPrivileges struct {
	Granted bool `json:"granted"`
}

type User struct {
	Data struct {
		Type  string `json:"type"`
		Id    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			Apikey     string `json:"apikey"`
			Email      string `json:"email"`
			FirstName  string `json:"first_name"`
			LastName   string `json:"last_name"`
			Privileges struct {
				Intelligence   UserPrivileges `json:"intelligence"`
				Monitor        UserPrivileges `json:"monitor"`
				MonitorPartner UserPrivileges `json:"monitor-partner"`
			} `json:"privileges"`
			Quotas     Quotas `json:"quotas"`
			Reputation int    `json:"reputation"`
			Status     string `json:"status"`
			UserSince  int    `json:"user_since"`
		} `json:"attributes"`
	} `json:"data"`
}

type Group struct {
	Data struct {
		Type  string `json:"type"`
		Id    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			AllowedScanners              []string `json:"allowed_scanners"`
			Apikey                       string   `json:"apikey"`
			AutoAddUsers                 []string `json:"auto_add_users"`
			BillingAddress               string   `json:"billing_address"`
			BillingCountry               string   `json:"billing_country"`
			BillingCountryIso            string   `json:"billing_country_iso"`
			BillingEmails                []string `json:"billing_emails"`
			BillingOrganizationLegalName string   `json:"billing_organization_legal_name"`
			BillingTaxId                 string   `json:"billing_tax_id"`
			ContactEmails                []string `json:"contact_emails"`
			Country                      string   `json:"country"`
			CountryIso                   string   `json:"country_iso"`
			DomainName                   string   `json:"domain_name"`
			Organization                 string   `json:"organization"`
			Privileges                   struct {
				Download     GroupPrivileges `json:"download"`
				FileFeed     GroupPrivileges `json:"file-feed"`
				Intelligence GroupPrivileges `json:"intelligence"`
				Monitor      GroupPrivileges `json:"monitor"`
				Retrohunt    GroupPrivileges `json:"retrohunt"`
				UrlFeed      GroupPrivileges `json:"url-feed"`
			} `json:"privileges"`
			Quotas Quotas `json:"quotas"`
		} `json:"attributes"`
	} `json:"data"`
}

func New(apikey string) *VirusTotal {
	return &VirusTotal{
		Apikey:  apikey,
		baseurl: "https://www.virustotal.com/api/v3",
	}
}

func (self *VirusTotal) post(path string, input interface{}) error {
	return self._post("POST", path, input)
}

func (self *VirusTotal) patch(path string, input interface{}) error {
	return self._post("PATCH", path, input)
}

func (self *VirusTotal) _delete(path string, input interface{}) {
	url := self.baseurl + path
	client := &http.Client{}
	if req, err := http.NewRequest("DELETE", url, nil); err == nil {
		req.Header.Add("x-apikey", self.Apikey)
		client.Do(req)
	}
}

func (self *VirusTotal) _post(verb string, path string, input interface{}) error {
	url := self.baseurl + path
	client := &http.Client{}

	var err error
	var req *http.Request
	var resp *http.Response
	var out []byte
	var data []byte

	if data, err = json.Marshal(input); err == nil {
		if req, err = http.NewRequest("POST", url, bytes.NewReader(data)); err == nil {
			req.Header.Add("x-apikey", self.Apikey)

			if resp, err = client.Do(req); err == nil {

				if out, err = ioutil.ReadAll(resp.Body); err == nil {

					var objmap map[string]*json.RawMessage
					if err = json.Unmarshal(out, &objmap); err == nil {
						if _, present := objmap["error"]; present {
							e := VtError{}
							if err = json.Unmarshal(*objmap["error"], &e); err == nil {
								return fmt.Errorf("%s: %s", e.Code, e.Message)
							}
						}

						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("unknown: oh boy, unknown")
}

func (self *VirusTotal) get(path string, result interface{}) error {
	url := self.baseurl + path
	client := &http.Client{}

	var err error
	var req *http.Request
	var resp *http.Response
	var out []byte

	if req, err = http.NewRequest("GET", url, nil); err == nil {
		req.Header.Add("x-apikey", self.Apikey)
		if resp, err = client.Do(req); err == nil {

			if out, err = ioutil.ReadAll(resp.Body); err == nil {
				var objmap map[string]*json.RawMessage
				if err = json.Unmarshal(out, &objmap); err == nil {

					if _, present := objmap["error"]; present {
						e := VtError{}
						if err = json.Unmarshal(*objmap["error"], &e); err == nil {
							return fmt.Errorf("%s: %s", e.Code, e.Message)
						}
					}

					if err = json.Unmarshal(out, &result); err == nil {
						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("unknown: oh boy, unknown")
}

func (self *VirusTotal) GetUser(userid string) (*User, error) {
	result := User{}
	if err := self.get("/users/"+userid, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (self *VirusTotal) GetGroup(groupid string) (*Group, error) {
	result := Group{}
	if err := self.get("/groups/"+groupid, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type Ruleset struct {
	Type  string `json:"type"`
	Id    string `json:"id"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
	Attributes struct {
		CreationDate       int      `json:"creation_date"`
		Enabled            bool     `json:"enabled"`
		Limit              int      `json:"limit"`
		ModifcationDate    int      `json:"modification_date"`
		Name               string   `json:"name"`
		NotificationEmails []string `json:"notification_emails"`
		Rules              string   `json:"rules"`
	} `json:"attributes"`
}

type Rulesets struct {
	Data []Ruleset `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
	Links struct {
		Self string `json:"self"`
		Next string `json:"next"`
	}
}

func (self *VirusTotal) GetHuntingRulesets() (*Rulesets, error) {
	result := Rulesets{}
	if err := self.get("/intelligence/hunting_rulesets", &result); err != nil {
		return nil, err
	}
	return &result, nil

}

func (self *VirusTotal) PostHuntingRuleset(rule *Ruleset) error {
	return self.post("intelligence/hunting_ruleset", rule)
}

type RulesetR struct {
	Data Ruleset `json:"data"`
}

func (self *VirusTotal) GetHuntingRuleset(ruleid string) (*RulesetR, error) {
	result := RulesetR{}
	if err := self.get("/intelligence/hunting_rulesets/"+ruleid, &result); err != nil {
		return nil, err
	}
	return &result, nil

}

func (self *VirusTotal) PatchHuntingRuleset(ruleid string, rule *Ruleset) error {
	return self.patch("/intelligence/hunting_rulesets"+ruleid, rule)
}

type Exiftool struct {
	CharacterSet             string `json:"CharaterSet"`
	CodeSize                 string `json:"CodeSize"`
	Comments                 string `json:"Comments"`
	CompanyName              string `json:"CompanyName"`
	EntryPoint               string `json:"EntryPoint"`
	FileDescription          string `json:"FileDescription"`
	FileFlagsMask            string `json:"FileFlagsMask"`
	FileOS                   string `json:"FileOS"`
	FileSubtype              string `json:"FileSubtype"`
	FileType                 string `json:"FileType"`
	FileTypeExtension        string `json:"FileTypeExtension"`
	FileVersionNumber        string `json:"FileVersionNumber"`
	ImageFileCharacteristics string `json:"ImageFileCharacteristics"`
	ImageVersion             string `json:"ImageVersion"`
	InalFilename             string `json:"InalFilename"`
	InitializedDataSize      string `json:"InitializedDataSize"`
	LanguageCode             string `json:"LanguageCode"`
	LegalCopyright           string `json:"LegalCopyright"`
	LegalTrademarks          string `json:"LegalTrademarks"`
	LinkerVersion            string `json:"LinkerVersion"`
	MIMEType                 string `json:"MIMEType"`
	MachineType              string `json:"MachineType"`
	OSVersion                string `json:"OSVersion"`
	ObjectFileType           string `json:"ObjectFileType"`
	PEType                   string `json:"PEType"`
	ProductName              string `json:"ProductName"`
	ProductVersionNumber     string `json:"ProductVersionNumber"`
	Subsystem                string `json:"Subsystem"`
	SubsystemVersion         string `json:"SubsystemVersion"`
	TimeStamp                string `json:"TimeStamp"`
	UninitializedDataSize    string `json:"UninitializedDataSize"`
}

type AnalysisResult struct {
	Category      string `json:"category"`
	EngineName    string `json:"engine_name"`
	EngineUpdate  string `json:"engine_update"`
	EngineVersion string `json:"engine_version"`
	Method        string `json:"method"`
	Result        string `json:"result"`
}

type ResourceDetail struct {
	Chi2     float64 `json:"chi2"`
	Entropy  float64 `json:"entropy"`
	Filetype string  `json:"filetype"`
	Lang     string  `json:"lang"`
	Sha256   string  `json:"sha256"`
	Type     string  `json:"type"`
}

type Section struct {
	Entropy        float64 `json:"entropy"`
	Md5            string  `json:"md5"`
	Name           string  `json:"name"`
	RawSize        int     `json:"raw_size"`
	VirtualAddress int     `json:"virtual_address"`
	VirtualSize    int     `json:"virtual_size"`
}

type PeInfo struct {
	EntryPoint  int                 `json:"entry_point"`
	Imphash     string              `json:"imphash"`
	Imports     map[string][]string `json:"imports"`
	MachineType int                 `json:"machine_type"`
	Overlay     struct {
		Chi2     float64 `json:"chi2"`
		Entropy  float64 `json:"entropy"`
		Filetype string  `json:"filetype"`
		Md5      string  `json:"md5"`
		Offset   int     `json:"offset"`
		Size     int     `json:"size"`
	} `json:"overlay"`
	ResourceDetails []ResourceDetail `json:"resource_details"`
	Sections        []Section        `json:"sections"`
	Timestamp       int              `json:"timestamp"`
}

type File struct {
	Authentihash        string                    `json:"authentihash"`
	CreationDate        int                       `json:"creation_date"`
	Exiftool            Exiftool                  `json:"exiftool"`
	FirstSubmissionDate int                       `json:"first_submission_date"`
	LastAnalysisDate    int                       `json:"last_analysis_date"`
	LastAnalysisResults map[string]AnalysisResult `json:"last_analysis_results"`
	LastAnalysisStats   struct {
		Failure         int `json:"failure"`
		Harmless        int `json:"harmless"`
		Malicious       int `json:"malicious"`
		Suspicious      int `json:"suspicious"`
		Timeout         int `json:"timeout"`
		TypeUnsupported int `json:"type-unsupported"`
		Undetected      int `json:"undetected"`
	} `json:"last_analysis_status"`
	LastModificationDate int      `json:"last_modification_date"`
	LastSubmissionDate   int      `json:"last_submission_date"`
	Magic                string   `json:"magic"`
	Md5                  string   `json:"md5"`
	MeaningfulName       string   `json:"meaningful_name"`
	names                []string `json:"names"`
	PeInfo               PeInfo   `json:"pe_info,omitempty"`
	Reputation           int      `json:"reputation"`
	Sha1                 string   `json:"sha1"`
	Sha256               string   `json:"sha256"`
	SignatureInfo        struct {
		Comments    string `json:"comments"`
		Copyright   string `json:"copyright"`
		Description string `json:"description"`
		Product     string `json:"product"`
	} `json:"signature_info"`
	Size          int      `json:"size"`
	Ssdeep        string   `json:"ssdeep"`
	Tags          []string `json:"tags"`
	TimeSubmitted int      `json:"times_submitted"`
	TotalVotes    struct {
		Harmless  int `json:"harmless"`
		Malicious int `json:"malicious"`
	} `json:"total_votes"`
	Trid []struct {
		Filetype    string  `json:"file_type"`
		Probability float64 `json:"probability"`
	}
	TypeDescription string `json:"type_description"`
	TypeTag         string `json:"type_tag"`
	UniqueSources   int    `json:"unique_sources"`
	Vhash           string `json:"vhash"`
}

type HuntingFileContextAttributes struct {
	Body    string   `json:"hunting_notification_body"`
	Date    int      `json:"hunting_notification_date"`
	Id      string   `json:"hunting_notification_id"`
	Subject string   `json:"hunting_notification_subject"`
	Tags    []string `json:"hunting_notification_tags"`
}

type HuntingFile struct {
	Attributes        File                         `json:"attributes"`
	ContextAttributes HuntingFileContextAttributes `json:"context_attributes"`
	Id                string                       `json:"id"`
	Links             struct {
		Self string `json:"self"`
	}
	Type string `json:"type"`
}

type HuntingFiles struct {
	Data  []HuntingFile `json:"data"`
	Links struct {
		Self string `json:"self"`
		Next string `json:"next"`
	}
	Meta struct {
		Cursor string `json:"cursor"`
	}
}

func (self *VirusTotal) GetHuntingNotificationFiles() (*HuntingFiles, error) {
	result := HuntingFiles{}
	if err := self.get("/intelligence/hunting_notification_files", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type HashAnalysis struct {
	Data []struct {
		Id         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			AnalysisResults map[string]AnalysisResult `json:"analysis_results"`
			Date            int                       `json:"date"`
			DetectionsCount int                       `json:"detections_count"`
			Sha256          string                    `json:"sha256"`
			Tags            []string                  `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

func (self *VirusTotal) GetHashAnalysis(sha256 string) (*HashAnalysis, error) {
	result := HashAnalysis{}
	if err := self.get(fmt.Sprintf("/monitor_partner/hashes/%s/analyses", sha256), &result); err != nil {
		return nil, err
	}
	fmt.Println(result)
	return &result, nil
}
