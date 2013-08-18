# redefinable top level domain blacklist, used to ignore specific domain TLDs
global tld_blacklist: set[string] = {
        "foo",
	"org",
} &redef;
