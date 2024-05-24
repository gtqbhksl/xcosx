package vuln

import (
	"fmt"
	bolt "go.etcd.io/bbolt"
	"log"
	"strings"
	"xcosx/types"
)

type dbvulns struct {
	version string
	cve     string
}
type Existvulns struct {
	Packname   string
	Version    string
	Cve        string
	Fixversion string
}

func ReadDB(osname string, packagename string) []dbvulns {
	var dbvulnS []dbvulns
	// 打开数据库
	db, err := bolt.Open("./xcosx.db", 0600, &bolt.Options{Timeout: 3600})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 读取数据
	err = db.View(func(tx *bolt.Tx) error {

		// 获取OSname桶
		osNameBucket := tx.Bucket([]byte(osname))
		if osNameBucket == nil {
			return fmt.Errorf("OSname bucket not found")
		}

		// 获取packname桶
		packNameBucket := osNameBucket.Bucket([]byte(packagename))
		if packNameBucket == nil {
			return fmt.Errorf("packname bucket not found")
		}
		// 遍历version桶下的CVE信息
		err := packNameBucket.ForEach(func(k, v []byte) error {
			//fmt.Printf("version: %s, cve: %s\n", k, v)
			dbvuln := dbvulns{string(k), string(v)}
			dbvulnS = append(dbvulnS, dbvuln)
			return nil
		})

		if err != nil {
			return err
		}
		return nil
	})
	return dbvulnS
}

func Compare(osname string, packname string, version string, release string) []Existvulns {
	var existvuln []Existvulns
	dbvulnS := ReadDB(osname, packname)
	for _, dbvuln := range dbvulnS {

		verlens := strings.Split(dbvuln.version, ":")
		vsver := verlens[len(verlens)-1]
		vsvers := strings.Split(vsver, "-")

		vsverVersion := vsvers[0]
		vsverRelease := vsvers[1]

		versions := strings.Split(version, ".")
		vsverVersions := strings.Split(vsverVersion, ".")

		for i, versionss := range versions {
			if strings.Compare(versionss, vsverVersions[i]) < 0 {
				//优化比较，先比较位数再比较大小
				if len(versionss) == len(vsverVersions[i]) {
					if versionss < vsverVersions[i] {
						//fmt.Println("优化比较结果：", versionss, "<", vsverVersions[i])
						existvuln = append(existvuln, Existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
						return existvuln
					}
				} else {
					if len(versionss) < len(vsverVersions[i]) {
						//fmt.Println("优化比较结果：", versionss, "<", vsverVersions[i])
						existvuln = append(existvuln, Existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
						return existvuln
					}
				}
			}
		}

		releases := strings.Split(release, ".")
		vsverReleases := strings.Split(vsverRelease, ".")

		for i, releasess := range releases {
			//优化比较，先比较位数再比较大小
			if len(releasess) == len(vsverReleases[i]) {
				if releasess < vsverReleases[i] {
					//fmt.Println("优化比较结果：", releasess, "<", vsverReleases[i])
					existvuln = append(existvuln, Existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
					return existvuln
				}
			} else {
				if len(releasess) < len(vsverReleases[i]) {
					//fmt.Println("优化比较结果：", releasess, "<", vsverReleases[i])
					existvuln = append(existvuln, Existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
					return existvuln
				}
			}
		}
	}
	if len(existvuln) == 0 {
		return nil
	}
	return existvuln
}

func PackageVulnScan(mergedLayer types.ArtifactDetail) [][]Existvulns {
	//// 打开数据库
	//db, err := bolt.Open("xcosx.db", 0600, &bolt.Options{Timeout: 60})
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer db.Close()

	var Existvuln [][]Existvulns
	var osname string
	//fmt.Println(mergedLayer.Packages)
	if mergedLayer.OS.Family == "alinos" {
		osvers := strings.Split(mergedLayer.OS.Name, ".")
		osname = mergedLayer.OS.Family + osvers[0]
	} else {
		osname = mergedLayer.OS.Family + mergedLayer.OS.Name
	}

	for _, pkg := range mergedLayer.Packages {
		PackExistvuln := Compare(osname, pkg.Name, pkg.Version, pkg.Release)
		if PackExistvuln != nil {
			Existvuln = append(Existvuln, PackExistvuln)
		}
	}

	return Existvuln

}
