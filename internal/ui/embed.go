package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

//go:embed templates
var templateFS embed.FS

// funcMap expone helpers de plantilla: "date" (fecha con layout Go, reemplaza
// el filtro |date de Jinja) y "slug" (normalización D4, reemplaza DomainClean).
var funcMap = template.FuncMap{
	"date": func(value any, layout string) string {
		switch t := value.(type) {
		case time.Time:
			return t.Format(layout)
		case string:
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				return parsed.Format(layout)
			}
			return t
		default:
			return fmt.Sprint(value)
		}
	},
	"slug": domain.DomainSlug,
}

// pageNames son las páginas que definen el bloque "content" sobre "base".
// El nombre del archivo coincide con el valor de ?tab=.
var pageNames = []string{"overview", "sites", "exclusions", "iprules", "logs", "rollback"}

// templates contiene un set de plantillas por página (base + content) y una
// plantilla standalone para login. Se parsean una vez al iniciar el paquete.
var templates = parseTemplates()

// parseTemplates construye el mapa de plantillas: por cada página se parsean
// base.html + {page}.html en un set propio (evita colisiones del bloque
// "content" entre páginas); login.html es un documento completo.
func parseTemplates() map[string]*template.Template {
	m := make(map[string]*template.Template, len(pageNames)+1)
	for _, page := range pageNames {
		t := template.New("base").Funcs(funcMap)
		t = template.Must(t.Parse(mustRead("templates/base.html")))
		t = template.Must(t.Parse(mustRead("templates/" + page + ".html")))
		m[page] = t
	}
	m["login"] = template.Must(template.New("login").Funcs(funcMap).Parse(mustRead("templates/login.html")))
	return m
}

// mustRead lee un archivo embebido; ante un error el programa no puede
// funcionar (templates obligatorios), por eso paniquea en init.
func mustRead(path string) string {
	content, err := fs.ReadFile(templateFS, path)
	if err != nil {
		panic(fmt.Sprintf("plantilla embebida %s: %v", path, err))
	}
	return string(content)
}
