package authzone

type Principal struct {
	Issuer   string
	Subject  string
	Email    string
	Picture  string
	Metadata map[string]string

	home   Zone
	roles  map[Zone][]string
	legacy bool
}
