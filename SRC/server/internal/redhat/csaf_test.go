package redhat
import "testing"

// A realistic (trimmed) Red Hat CSAF VEX document: openssl fixed in RHEL 9,
// still affected in RHEL 8, plus a non-RHEL product that must be ignored.
const sample = `{
 "document":{"tracking":{"id":"CVE-2024-0001"},"aggregate_severity":{"text":"Important"}},
 "vulnerabilities":[{
   "cve":"CVE-2024-0001",
   "product_status":{
     "fixed":[
       "red_hat_enterprise_linux_9:openssl-1:3.0.7-27.el9_2.src",
       "red_hat_enterprise_linux_9:openssl-1:3.0.7-27.el9_2.x86_64",
       "openshift_container_platform_4:something-0:1.2-3.src"
     ],
     "known_affected":[
       "red_hat_enterprise_linux_8:openssl-1:1.1.1k-9.el8.src"
     ]
   },
   "threats":[{"category":"impact","details":"Important"}]
 }]
}`

func TestParseCSAF(t *testing.T){
  advs, err := ParseCSAF([]byte(sample))
  if err != nil { t.Fatal(err) }
  // Expect: el9 resolved (openssl, fixed 1:3.0.7-27.el9_2) + el8 open (openssl).
  // The .x86_64 dup and the OpenShift product must be dropped.
  if len(advs) != 2 { t.Fatalf("want 2 advisories, got %d: %+v", len(advs), advs) }
  var el9, el8 bool
  for _, a := range advs {
    if a.SourcePackage!="openssl" { t.Errorf("unexpected pkg %q", a.SourcePackage) }
    switch a.Release {
    case "el9":
      el9=true
      if a.Status!="resolved" || a.FixedVersion!="1:3.0.7-27.el9_2" { t.Errorf("el9 wrong: %+v", a) }
    case "el8":
      el8=true
      if a.Status!="open" || a.FixedVersion!="" { t.Errorf("el8 wrong: %+v", a) }
    default: t.Errorf("unexpected release %q", a.Release)
    }
    if a.Urgency!="Important" { t.Errorf("severity not carried: %+v", a) }
  }
  if !el9||!el8 { t.Errorf("missing releases el9=%v el8=%v", el9, el8) }
}

func TestParseProductID(t *testing.T){
  rel,name,evr,arch,ok := parseProductID("red_hat_enterprise_linux_9:python3.9-0:3.9.18-1.el9.src")
  if !ok||rel!="el9"||name!="python3.9"||evr!="0:3.9.18-1.el9"||arch!="src" {
    t.Fatalf("got rel=%q name=%q evr=%q arch=%q ok=%v", rel,name,evr,arch,ok)
  }
  // hyphenated name
  _,name2,_,_,ok2 := parseProductID("red_hat_enterprise_linux_9:python3-libs-0:3.9.18-1.el9.x86_64")
  if !ok2 || name2!="python3-libs" { t.Fatalf("hyphenated name parse: %q ok=%v", name2, ok2) }
  // non-RHEL -> skip
  if _,_,_,_,ok3 := parseProductID("openshift_container_platform_4:foo-0:1-2.src"); ok3 {
    t.Fatalf("non-RHEL product should be skipped")
  }
}
