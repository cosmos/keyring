package keyring

import (
	"os"
	"testing"
)

func TestFileKeyringSetWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}

func TestFileKeyringGetWithSlashes(t *testing.T) {
	k := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	item := Item{Key: "https://aws-sso-portal.awsapps.com/start", Data: []byte("https://aws-sso-portal.awsapps.com/start")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatal(err)
	}
}

func TestFilenameWithBadChars(t *testing.T) {
	a := `abc/.././123`
	e := filenameEscape(a)
	if e != `abc%2F..%2F.%2F123` {
		t.Fatalf("Unexpected result from filenameEscape: %s", e)
	}

	b := filenameUnescape(e)
	if b != a {
		t.Fatal("Unexpected filenameEscape")
	}
}

type ChangePwGenerator struct {
	changePwIndex   int
	changePwStrings []string
}

func (generator *ChangePwGenerator) nextPassword() string {
	nextPassword := generator.changePwStrings[generator.changePwIndex]
	generator.changePwIndex++
	return nextPassword
}

func ChangePwStringPrompt(values []string) PromptFunc {
	generator := &ChangePwGenerator{
		changePwStrings: values,
	}
	return func(_ string) (string, error) {
		return generator.nextPassword(), nil
	}
}

func TestFileKeyringChangepw(t *testing.T) {
	k := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: ChangePwStringPrompt([]string{"no more secrets", "new secrets"}),
	}
	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Changepw(item.Key); err != nil {
		t.Fatal(err)
	}

	k2 := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: FixedStringPrompt("new secrets"),
	}

	foundItem, err := k2.Get(`llamas`)
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}
