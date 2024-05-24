package main

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"log"
	"os"
	"strings"
	"xcosx/analyzer/vuln"

	"xcosx/analyzer"
	_ "xcosx/analyzer/all"
	"xcosx/analyzer/config"
	"xcosx/applier"
	"xcosx/artifact"
	aimage "xcosx/artifact/image"
	"xcosx/artifact/local"
	"xcosx/cache"
	"xcosx/image"
	"xcosx/types"
	"xcosx/utils"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() (err error) {
	app := &cli.App{
		Name:  "xcosx",
		Usage: "XC（信创）+OS（操作系统）+X（X卫士）。面向信创操作系统的容器、镜像、文件系统扫描工具。支持扫描敏感信息、软件包漏洞、webshell、弱口令等问题",
		Commands: []*cli.Command{
			{
				Name:    "image",
				Aliases: []string{"img"},
				Usage:   "inspect a container image,扫描容器镜像",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "conf-policy",
						Usage: "policy paths，只扫描的路径",
					},
					&cli.StringSliceFlag{
						Name:  "skip-files",
						Usage: "skip files，跳过的文件",
					},
					&cli.StringSliceFlag{
						Name:  "skip-dirs",
						Usage: "skip dirs，跳过的目录",
					},
				},
				Action: globalOption(imageAction),
			},
			{
				Name:    "archive",
				Aliases: []string{"ar"},
				Usage:   "inspect an image archive，扫描镜像文件 tar",
				Action:  globalOption(archiveAction),
			},
			{
				Name:    "filesystem",
				Aliases: []string{"fs"},
				Usage:   "inspect a local directory，扫描本地文件系统",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "namespace",
						Usage: "namespaces，名称",
						Value: cli.NewStringSlice("appshield"),
					},
					&cli.StringSliceFlag{
						Name:  "policy",
						Usage: "policy paths，目录",
					},
					&cli.StringSliceFlag{
						Name:  "skip-files",
						Usage: "skip files，跳过的文件",
					},
					&cli.StringSliceFlag{
						Name:  "skip-dirs",
						Usage: "skip dirs，跳过的目录",
					},
				},
				Action: globalOption(fsAction),
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "clear", Aliases: []string{"s"}, Usage: "clear cache，清除缓存"},
			//&cli.StringFlag{
			//	Name:    "cache",
			//	Aliases: []string{"c"},
			//	Usage:   "cache backend (e.g. redis://localhost:6379)",
			//},
		},
	}
	return app.Run(os.Args)
}

func globalOption(f func(*cli.Context, cache.Cache) error) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		cacheClient, err := initializeCache(c.String("cache"))
		if err != nil {
			return err
		}
		defer cacheClient.Close()

		clearCache := c.Bool("clear")
		if clearCache {
			if err := cacheClient.Clear(); err != nil {
				return xerrors.Errorf("%w", err)
			}
			return nil
		}
		return f(c, cacheClient)
	}
}

func initializeCache(backend string) (cache.Cache, error) {
	var cacheClient cache.Cache
	var err error

	if strings.HasPrefix(backend, "redis://") {
		cacheClient = cache.NewRedisCache(&redis.Options{
			Addr: strings.TrimPrefix(backend, "redis://"),
		}, 0)
	} else {
		cacheClient, err = cache.NewFSCache(utils.CacheDir())
	}
	return cacheClient, err
}

func imageAction(c *cli.Context, fsCache cache.Cache) error {
	artifactOpt := artifact.Option{
		SkipFiles: c.StringSlice("skip-files"),
		SkipDirs:  c.StringSlice("skip-dirs"),

		MisconfScannerOption: config.ScannerOption{
			PolicyPaths: c.StringSlice("policy"),
		},
	}

	art, cleanup, err := imageArtifact(c.Context, c.Args().First(), fsCache, artifactOpt)
	if err != nil {
		return err
	}
	defer cleanup()
	return inspect(c.Context, art, fsCache)
}

func archiveAction(c *cli.Context, fsCache cache.Cache) error {
	art, err := archiveImageArtifact(c.Args().First(), fsCache)
	if err != nil {
		return err
	}
	return inspect(c.Context, art, fsCache)
}

func fsAction(c *cli.Context, fsCache cache.Cache) error {
	artifactOpt := artifact.Option{
		SkipFiles: c.StringSlice("skip-files"),
		SkipDirs:  c.StringSlice("skip-dirs"),

		MisconfScannerOption: config.ScannerOption{
			Namespaces:  []string{"appshield"},
			PolicyPaths: c.StringSlice("policy"),
		},
	}

	art, err := local.NewArtifact(c.Args().First(), fsCache, artifactOpt)
	if err != nil {
		return err
	}

	return inspect(c.Context, art, fsCache)
}

func inspect(ctx context.Context, art artifact.Artifact, c cache.LocalArtifactCache) error {
	imageInfo, err := art.Inspect(ctx)
	if err != nil {
		return err
	}

	a := applier.NewApplier(c)
	mergedLayer, err := a.ApplyLayers(imageInfo.ID, imageInfo.BlobIDs)

	if err != nil {
		switch err {
		case analyzer.ErrUnknownOS, analyzer.ErrNoPkgsDetected:
			fmt.Printf("WARN: %s 只是一个提醒，不是bug\n", err)
		default:
			return err
		}
	}
	Existvuln := vuln.PackageVulnScan(mergedLayer)
	fmt.Println("Target:", imageInfo.Name)
	if len(imageInfo.ImageMetadata.RepoTags) > 0 {
		fmt.Printf("镜像元数据RepoTags: %v\n", imageInfo.ImageMetadata.RepoTags)
		fmt.Printf("镜像元数据RepoDigests: %v\n", imageInfo.ImageMetadata.RepoDigests)
	}

	fmt.Printf("操作系统信息：名称[%s] 版本：[%s] \n", mergedLayer.OS.Family, mergedLayer.OS.Name)

	fmt.Printf("镜像软件包数量: %d , 有 %d 个存在漏洞的软件包\n", len(mergedLayer.Packages), len(Existvuln))
	fmt.Printf("%-20s %-20s %-20s %-20s\n", "存在漏洞的软件包", "版本", "漏洞", "漏洞修复版本")
	for _, pkgs := range Existvuln {
		for _, pkg := range pkgs {
			fmt.Printf("%-20s %-20s 	%-20s 	%-20s\n", pkg.Packname, pkg.Version, pkg.Cve, pkg.Fixversion)
		}
	}

	for _, app := range mergedLayer.Applications {
		fmt.Printf("%s (%s): %d\n", app.Type, app.FilePath, len(app.Libraries))
	}
	for _, weakpass := range mergedLayer.Weakpasses {
		fmt.Printf("弱口令: Type=%s Username=(%s) Password=(%s)\n", weakpass.Type, weakpass.Username, weakpass.Password)
	}
	for _, secret := range mergedLayer.Secrets {
		for _, finding := range secret.Findings {
			fmt.Printf("敏感信息: %s File=%s Secret=(%s) \n", finding.Title, secret.FilePath, finding.Match)
		}
	}
	for _, webshell := range mergedLayer.WebshellResult {
		fmt.Printf("WebShell: File=%s Score=%s Source=%s  //Regular expression:正则匹配 Neural Networks:神经网络识别 \n", webshell.FilePath, webshell.Score, webshell.Source)
	}
	if len(mergedLayer.Misconfigurations) > 0 {
		fmt.Println("Misconfigurations:")
	}
	for _, misconf := range mergedLayer.Misconfigurations {
		fmt.Printf("  %s: failures %d, warnings %d\n", misconf.FilePath, len(misconf.Failures), len(misconf.Warnings))
		for _, failure := range misconf.Failures {
			fmt.Printf("    %s: %s\n", failure.ID, failure.Message)
		}
	}
	return nil
}

func imageArtifact(ctx context.Context, imageName string, c cache.ArtifactCache,
	artifactOpt artifact.Option) (artifact.Artifact, func(), error) {
	img, cleanup, err := image.NewContainerImage(ctx, imageName, types.DockerOption{})
	if err != nil {
		return nil, func() {}, err
	}

	art, err := aimage.NewArtifact(img, c, artifactOpt)
	if err != nil {
		return nil, func() {}, err
	}
	return art, cleanup, nil
}

func archiveImageArtifact(imagePath string, c cache.ArtifactCache) (artifact.Artifact, error) {
	img, err := image.NewArchiveImage(imagePath)
	if err != nil {
		return nil, err
	}

	art, err := aimage.NewArtifact(img, c, artifact.Option{})
	if err != nil {
		return nil, err
	}
	return art, nil
}
