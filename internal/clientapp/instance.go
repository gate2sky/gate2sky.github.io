package clientapp

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// An instance of the app writes where its UI listens, so that starting it
// again shows the running one's window instead of opening a second app.
type instance struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// Publish records this instance at path; the returned func removes it.
func (u *UI) Publish(path string) (func(), error) {
	b, _ := json.Marshal(instance{"http://" + u.addr, u.token})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return func() {}, err
	}
	return func() { os.Remove(path) }, nil
}

// ShowRunning asks the instance recorded at path, if one is running, to
// show its window, and reports whether it did.
func ShowRunning(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var in instance
	if json.Unmarshal(b, &in) != nil || in.URL == "" {
		return false
	}
	req, _ := http.NewRequest(http.MethodPost, in.URL+"/api/show", nil)
	req.Header.Set("X-Token", in.Token)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent
}
