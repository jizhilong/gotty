package utils

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/fatih/structs"
	"github.com/yudai/hcl"
)

func FullfillDefaultValues(struct_ interface{}) (err error) {
	o := structs.New(struct_)

	for _, field := range o.Fields() {
		defaultValue := field.Tag("default")
		if defaultValue == "" {
			continue
		}
		var val interface{}
		switch field.Kind() {
		case reflect.String:
			val = defaultValue
		case reflect.Bool:
			if defaultValue == "true" {
				val = true
			} else if defaultValue == "false" {
				val = false
			} else {
				return errors.New("invalid bool expression")
			}
		case reflect.Int:
			val, err = strconv.Atoi(defaultValue)
			if err != nil {
				return err
			}
		default:
			val = field.Value()
		}
		field.Set(val)
	}
	return nil
}

func GenerateFlags(options ...interface{}) (flags []cli.Flag, mappings map[string]string, err error) {
	mappings = make(map[string]string)

	for _, struct_ := range options {
		o := structs.New(struct_)
		for _, field := range o.Fields() {
			flagName := field.Tag("flagName")
			if flagName == "" {
				continue
			}
			mappings[flagName] = field.Name()
			flagShortName := field.Tag("flagSName")
			flagDescription := field.Tag("flagDescribe")

			envName := "GOTTY_" + strings.ToUpper(strings.Join(strings.Split(flagName, "-"), "_"))

			if flagShortName != "" {
				flagName += ", " + flagShortName
			}

			switch field.Kind() {
			case reflect.String:
				flags = append(flags, cli.StringFlag{
					Name:   flagName,
					Value:  field.Value().(string),
					Usage:  flagDescription,
					EnvVar: envName,
				})
			case reflect.Bool:
				flags = append(flags, cli.BoolFlag{
					Name:   flagName,
					Usage:  flagDescription,
					EnvVar: envName,
				})
			case reflect.Int:
				flags = append(flags, cli.IntFlag{
					Name:   flagName,
					Value:  field.Value().(int),
					Usage:  flagDescription,
					EnvVar: envName,
				})
			default:
				return flags, mappings, errors.New("Unsupported type: " + field.Name())
			}
		}
	}

	return
}

func ApplyFlags(
	flags []cli.Flag,
	mappingHint map[string]string,
	c *cli.Context,
	options ...interface{},
) {

	objects := make([]*structs.Struct, len(options))
	for i, struct_ := range options {
		objects[i] = structs.New(struct_)
	}

	for flagName, fieldName := range mappingHint {
		if !c.IsSet(flagName) {
			continue
		}
		var field *structs.Field
		var ok bool
		for _, o := range objects {
			field, ok = o.FieldOk(fieldName)
			if ok {
				break
			}
		}
		if field == nil {
			continue
		}
		var val interface{}
		switch field.Kind() {
		case reflect.String:
			val = c.String(flagName)
		case reflect.Bool:
			val = c.Bool(flagName)
		case reflect.Int:
			val = c.Int(flagName)
		}
		field.Set(val)
	}
}

func ApplyConfigFile(filePath string, options ...interface{}) error {
	filePath = ExpandHomeDir(filePath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return err
	}

	fileString := []byte{}
	log.Printf("Loading config file at: %s", filePath)
	fileString, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	for _, object := range options {
		if err := hcl.Decode(object, string(fileString)); err != nil {
			return err
		}
	}

	return nil
}
