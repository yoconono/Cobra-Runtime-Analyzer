package inventory
import "testing"
func TestParseRpmInstalled(t *testing.T){
  // Simulated `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n'`
  sample := "openssl\t1\t3.0.7\t27.el9_2\topenssl-3.0.7-27.el9_2.src.rpm\tx86_64\n" +
            "bash\t0\t5.1.8\t9.el9\tbash-5.1.8-9.el9.src.rpm\tx86_64\n" +
            "kernel\t0\t5.14.0\t362.el9\tkernel-5.14.0-362.el9.src.rpm\tx86_64\n" +
            "gpg-pubkey\t0\tabcdef\t01\t(none)\t(none)\n" +   // must be skipped
            "python3-libs\t0\t3.9.18\t1.el9\tpython3.9-3.9.18-1.el9.src.rpm\tx86_64\n"
  pkgs := parseRpmInstalled([]byte(sample))
  if len(pkgs)!=4 { t.Fatalf("want 4 pkgs (gpg-pubkey skipped), got %d", len(pkgs)) }
  by := map[string]struct{Ver,Src,SrcVer string}{}
  for _,p := range pkgs { by[p.Name]=struct{Ver,Src,SrcVer string}{p.Version,p.Source,p.SourceVersion} }
  if got:=by["openssl"]; got.Ver!="1:3.0.7-27.el9_2"||got.Src!="openssl"||got.SrcVer!="3.0.7-27.el9_2" {
    t.Errorf("openssl parsed wrong: %+v", got)
  }
  if got:=by["bash"]; got.Ver!="5.1.8-9.el9" { t.Errorf("bash EVR wrong (epoch 0 should be omitted): %q", got.Ver) }
  // source name with a dot+digits (python3.9) must resolve to python3.9, not python3
  if got:=by["python3-libs"]; got.Src!="python3.9"||got.SrcVer!="3.9.18-1.el9" {
    t.Errorf("python3-libs source parse wrong: %+v", got)
  }
}
func TestParseSourceRPM(t *testing.T){
  cases := []struct{in,name,evr string}{
    {"openssl-3.0.7-27.el9_2.src.rpm","openssl","3.0.7-27.el9_2"},
    {"python3.9-3.9.18-1.el9.src.rpm","python3.9","3.9.18-1.el9"},
    {"kernel-5.14.0-362.28.1.el9_4.src.rpm","kernel","5.14.0-362.28.1.el9_4"},
    {"(none)","",""},
    {"","",""},
  }
  for _,c := range cases {
    n,e := parseSourceRPM(c.in)
    if n!=c.name||e!=c.evr { t.Errorf("parseSourceRPM(%q)=(%q,%q) want (%q,%q)",c.in,n,e,c.name,c.evr) }
  }
}
func TestOSFamily(t *testing.T){
  rhel := []string{"rhel","centos","fedora","rocky","almalinux","ol","amzn"}
  for _,id := range rhel { if osFamily(id)!="rhel" { t.Errorf("osFamily(%q) != rhel",id) } }
  deb := []string{"debian","ubuntu","linuxmint","raspbian"}
  for _,id := range deb { if osFamily(id)!="debian" { t.Errorf("osFamily(%q) != debian",id) } }
}
