package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	name     = "ikarus"
	category = "av"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	path string

	// es is the elasticsearch database object
	es elasticsearch.Database
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"ikarus" structs:"ikarus"`
}

// Ikarus json object
type Ikarus struct {
	Results ResultsData `json:"ikarus"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Database string `json:"database" structs:"database"`
	Updated  string `json:"updated" structs:"updated"`
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
	Error    string `json:"error,omitempty" structs:"error,omitempty"`
}

func assert(err error) {
	if err != nil {
		if err.Error() != "exit status 1" {
			log.WithFields(log.Fields{
				"plugin":   name,
				"category": category,
				"path":     path,
			}).Fatal(err)
		}
	}
}

// AvScan performs antivirus scan
func AvScan(timeout int) Ikarus {

	var output string
	var avErr error

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log.Debug("running t3scan_l64")
	output, avErr = utils.RunCommand(ctx, "/opt/ikarus/t3scan_l64", path)
	if avErr != nil {
		// If fails try a second time
		time.Sleep(7 * time.Second)
		log.Debug("re-running t3scan_l64")
		output, avErr = utils.RunCommand(ctx, "/opt/ikarus/t3scan_l64", path)
		assert(avErr)
	}

	return Ikarus{Results: ParseIkarusOutput(output, avErr)}
}

// ParseIkarusOutput convert ikarus output into ResultsData struct
func ParseIkarusOutput(ikarusout string, avErr error) ResultsData {

	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("Ikarus Output: ", ikarusout)

	if avErr != nil {
		// ignore exit code 1 as that just means a virus was found
		if avErr.Error() != "exit status 1" {
			return ResultsData{Error: avErr.Error()}
		}
	}

	lines := strings.Split(ikarusout, "\n")

	//reT3Version := regexp.MustCompile(`IKARUS - T3SCAN\s+(.*)$`)
	//t3Version := reT3Version.FindStringSubmatch(lines[0])
	reEngine := regexp.MustCompile(`^\s+Engine version:\s+([0-9.]+)\s*$`)
	engine := reEngine.FindStringSubmatch(lines[1])
	reVdb := regexp.MustCompile(`^\s+VDB:\s+(.*)$`)
	vdb := reVdb.FindStringSubmatch(lines[2])
	isVersionInfoOk := vdb != nil && engine != nil

	virusFound := false
	virusSignatures := 0
	virusSignature := ""
	reSignature := regexp.MustCompile(`.*(Signature \d+)\s+[']([^']*)[']\s+found.*$`)
	reInfected := regexp.MustCompile(`.*1 file infected.*$`)
	for _, line := range lines {
		sigdata := reSignature.FindStringSubmatch(line)
		infected := reInfected.FindStringSubmatch(line)
		if len(line) != 0 && sigdata != nil && len(sigdata) == 3 {
			virusSignature = strings.TrimSpace(sigdata[2])
			virusSignatures = virusSignatures + 1
		}
		if infected != nil {
			virusFound = true
		}
	}
	isSignatureParsingOk := (virusSignatures == 0 && !virusFound || virusSignatures == 1 && virusFound)
	if !isSignatureParsingOk || !isVersionInfoOk {
		log.Error("[ERROR] when extracting virus scan results from output")
		log.Errorf("[ERROR] output was: \n%s", ikarusout)
		return ResultsData{Error: "Unable to parse ikarus output"}
	}

	ikarus := ResultsData{
		Infected: virusFound,
		Engine:   engine[1],
		Database: vdb[1],
		Updated:  getUpdatedDate(),
		Result:   virusSignature,
	}

	return ikarus
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, _ := time.Parse(layout, date)
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/opt/malice/UPDATED"); os.IsNotExist(err) {
		return BuildTime
	}
	updated, err := ioutil.ReadFile("/opt/malice/UPDATED")
	assert(err)
	return string(updated)
}

func updateAV(ctx context.Context) error {
	fmt.Println("Updating Ikarus...")

	fmt.Println(utils.RunCommand(ctx, "/opt/ikarus/t3update_l64", "-update"))

	// Update UPDATED file
	t := time.Now().Format("20060102")
	return ioutil.WriteFile("/opt/malice/UPDATED", []byte(t), 0644)
}

func getLinesOfFileAsArray(path string) []string {
	updated, err := ioutil.ReadFile(path)
	assert(err)
	return strings.Split(string(updated), "\n")
}

func didLicenseExpire() bool {
	if _, err := os.Stat("/opt/ikarus/t3cmd.ikkey"); os.IsNotExist(err) {
		log.Fatal("could not find Ikarus license file")
	}
	license, err := ioutil.ReadFile("/opt/ikarus/t3cmd.ikkey")
	assert(err)

	lines := strings.Split(string(license), "\n")
	// Extract Virus string and extract colon separated lines into an slice
	for _, line := range lines {
		if len(line) != 0 {
			if strings.Contains(line, "enddate") {
				expireDate := strings.TrimSpace(strings.TrimPrefix(line, "enddate"))
				t, err := time.Parse("2006-01-02", expireDate)
				if err != nil {
					log.Fatal(err)
				}
				log.WithFields(log.Fields{
					"plugin":   name,
					"category": category,
					"expired":  t.Before(time.Now()),
				}).Debug("Ikarus License Expires: ", t)
				return t.Before(time.Now())
			}
		}
	}

	log.Error("could not find expiration date in license file")
	return false
}

func generateMarkDownTable(a Ikarus) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("ikarus").Parse(tpl))

	err := t.Execute(&tplOut, a)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	checkIkarusBinaries()
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
	}).Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webAvScan(w http.ResponseWriter, r *http.Request) {

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
		}).Error(err)
	}
	defer file.Close()

	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
	}).Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	assert(err)
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)
	assert(err)

	if _, err = tmpfile.Write(data); err != nil {
		assert(err)
	}
	if err = tmpfile.Close(); err != nil {
		assert(err)
	}

	// Do AV scan
	path = tmpfile.Name()
	ikarus := AvScan(60)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(ikarus); err != nil {
		assert(err)
	}
}

func checkIkarusBinaries() {
	libFileInfo, err := os.Stat("/opt/ikarus/libT3_l64.so")
	assert(err)

	if libFileInfo.Mode().Perm()&0001 == 0 {
		assert(errors.New("libT3_l64.so is not executable! Use chmod +x to fix it!"))
	}

	scanBinaryFileInfo, err := os.Stat("/opt/ikarus/t3scan_l64")
	assert(err)

	if scanBinaryFileInfo.Mode().Perm()&0001 == 0 {
		assert(errors.New("t3scan_l64 is not executable! Use chmod +x to fix it!"))
	}

	updateBinaryFileInfo, err := os.Stat("/opt/ikarus/t3update_l64")
	assert(err)

	if updateBinaryFileInfo.Mode().Perm()&0001 == 0 {
		assert(errors.New("t3update_l64 is not executable! Use chmod +x to fix it!"))
	}
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "ikarus"
	app.Author = "betellen, danieljampen, blacktop"
	app.Email = "https://github.com/malice-plugins/ikarus"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice Ikarus AntiVirus Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results back to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  120,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {
				return updateAV(nil)
			},
		},
		{
			Name:  "web",
			Usage: "Create a Ikarus scan web service",
			Action: func(c *cli.Context) error {
				webService()
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		var err error

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err = filepath.Abs(c.Args().First())
			assert(err)

			if _, err = os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}

			checkIkarusBinaries()

			if didLicenseExpire() {
				log.Errorln("Ikarus license has expired")
				log.Errorln("please get a new one here: https://www.ikarussecurity.com/")
			}

			ikarus := AvScan(c.Int("timeout"))
			ikarus.Results.MarkDown = generateMarkDownTable(ikarus)
			// upsert into Database
			if len(c.String("elasticsearch")) > 0 {
				err := es.Init()
				if err != nil {
					return errors.Wrap(err, "failed to initalize elasticsearch")
				}
				err = es.StorePluginResults(database.PluginResults{
					ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
					Name:     name,
					Category: category,
					Data:     structs.Map(ikarus.Results),
				})
				if err != nil {
					return errors.Wrapf(err, "failed to index malice/%s results", name)
				}
			}

			if c.Bool("table") {
				fmt.Printf(ikarus.Results.MarkDown)
			} else {
				ikarus.Results.MarkDown = ""
				ikarusJSON, err := json.Marshal(ikarus)
				assert(err)
				if c.Bool("callback") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(ikarusJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(ikarusJSON))
			}
		} else {
			log.WithFields(log.Fields{
				"plugin":   name,
				"category": category,
			}).Fatal(fmt.Errorf("Please supply a file to scan with malice/ikarus"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
