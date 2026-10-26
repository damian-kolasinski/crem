package signing

import (
	"fmt"
	"slices"
	"strings"
)

// TemplateFields are the placeholders a Template may use.
var TemplateFields = []string{"app", "environment", "extension", "bundleId"}

// Template is a name with {field} placeholders, such as "PROFILE_BASE64_{environment}".
type Template struct {
	parts []templatePart
	raw   string
}

type templatePart struct {
	literal string
	field   string
}

// ParseTemplate parses a template, rejecting unknown or unterminated placeholders.
func ParseTemplate(raw string) (Template, error) {
	if raw == "" {
		return Template{}, fmt.Errorf("template is empty")
	}
	var parts []templatePart
	rest := raw
	for rest != "" {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			parts = append(parts, templatePart{literal: rest})
			break
		}
		if open > 0 {
			parts = append(parts, templatePart{literal: rest[:open]})
		}
		closing := strings.IndexByte(rest[open:], '}')
		if closing < 0 {
			return Template{}, fmt.Errorf("template %q has an unterminated placeholder", raw)
		}
		field := rest[open+1 : open+closing]
		if !slices.Contains(TemplateFields, field) {
			return Template{}, fmt.Errorf("template %q uses unknown placeholder {%s} (expected one of {%s})", raw, field, strings.Join(TemplateFields, "}, {"))
		}
		parts = append(parts, templatePart{field: field})
		rest = rest[open+closing+1:]
	}
	return Template{parts: parts, raw: raw}, nil
}

// MustParseTemplate parses a template known to be valid.
func MustParseTemplate(raw string) Template {
	template, err := ParseTemplate(raw)
	if err != nil {
		panic(err)
	}
	return template
}

// Uses reports whether the template contains the placeholder.
func (t Template) Uses(field string) bool {
	return slices.ContainsFunc(t.parts, func(part templatePart) bool { return part.field == field })
}

// Render replaces each placeholder with its value.
func (t Template) Render(values map[string]string) string {
	var builder strings.Builder
	for _, part := range t.parts {
		if part.field != "" {
			builder.WriteString(values[part.field])
		} else {
			builder.WriteString(part.literal)
		}
	}
	return builder.String()
}

func (t Template) String() string {
	return t.raw
}
