package main

import (
	// std
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	// external stuff
	git "github.com/go-git/go-git/v5"
	gplumbing "github.com/go-git/go-git/v5/plumbing"
	object "github.com/go-git/go-git/v5/plumbing/object"
	ghttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Types of possible git references
// BRANCH is for checking out the latest commit of branch
// TAG is for checking out specific tags/versions
// COMMIT is for checking out specific commit by hash
// TODO: make it work with tags/versions
type referenceType int8

const (
	BRANCH referenceType = iota
	COMMIT
	TAG
)

// localRepo class
type localRepo struct {
	path string
	repo *git.Repository
}

// Makes sure the latest version of the repo @ repo_url is present in the local_dir/repo_name directory
// Use gitlab personal access tokens for auth (can be generated with read-only permissions)
func initizalizeLocalRepo(repo_url, user, token, local_dir string) (*localRepo, error) {

	var repo *git.Repository
	var tree *git.Worktree
	var repo_name, path string
	var repo_name_regexp *regexp.Regexp = regexp.MustCompile(`[a-zA-Z0-9_-]+\.git$`)
	var credentials *ghttp.BasicAuth = &ghttp.BasicAuth{
		Username: user,
		Password: token,
	}
	var err error

	repo_name = repo_name_regexp.FindString(repo_url)
	if repo_name == "" {
		return nil, fmt.Errorf("Invalid repo url: %s, can't extract repo name", repo_url)
	}

	path = filepath.Join(local_dir, repo_name[:len(repo_name)-4])

	// making sure local_dir exists
	// should work with windows but it will give dirs some default permissions
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return nil, fmt.Errorf("Invalid local dir: %s, error: %s", local_dir, err)
	}

	// cloning without checking out so I don't have to checkout twice (because I do pull later anyway)
	repo, err = git.PlainClone(path, false, &git.CloneOptions{
		URL:        repo_url,
		NoCheckout: true,
		Auth:       credentials,
	})

	// PlainClone returns error on non-empty directory
	// pulling should be faster then deleting and cloning again
	if err == git.ErrRepositoryAlreadyExists {

		repo, err = git.PlainOpen(path)
		if err != nil {
			return nil, fmt.Errorf("Local repo %s already exists but can't be opened. Error: %s", repo_name, err)
		}

	} else if err != nil {
		return nil, fmt.Errorf("Cloning of %s failed. Error: %s", repo_name, err)
	}

	tree, err = repo.Worktree()
	if err != nil {
		return nil, err
	}

	err = tree.Pull(&git.PullOptions{
		RemoteName: "origin",
		Auth:       credentials,
	})
	if err == git.NoErrAlreadyUpToDate {
		log.Println("repo already up to date")
	} else if err != nil {
		return nil, err
	}

	return &localRepo{
		repo: repo,
		path: path,
	}, nil
}

func (local_repo *localRepo) getPath() string {
	return local_repo.path
}

// returns a slice of valid synapse objects present in the local repo
// TODO: maybe return date of last edit/basic info rom inside project config
func (local_repo *localRepo) getSynapseObjects() ([]os.FileInfo, error) {
	var contents []os.DirEntry
	var projects []os.FileInfo
	var err error

	contents, err = os.ReadDir(local_repo.path)

	for _, element := range contents {
		if element.IsDir() {
			if _, err = os.Stat(filepath.Join(local_repo.path, element.Name(), "config.xml")); err == nil {
				var info os.FileInfo
				info, err = element.Info()
				if err != nil {
					projects = append(projects, info)
				}
			}
		}
	}

	if len(projects) < 1 {
		return nil, fmt.Errorf("No viable projects found in repository")
	}

	return projects, nil
}

// TODO: return more info than just message and also search for tags associated with commits
func (local_repo *localRepo) getSynapseObjectCommits(synapse_object string) ([]string, error) {
	var commit_iter object.CommitIter
	var commit *object.Commit
	var output []string
	var containsSynapseObjectName = func(s string) bool {
		var synapse_object_regexp *regexp.Regexp = regexp.MustCompile(synapse_object)
		return synapse_object_regexp.Match([]byte(s))
	}
	var err error

	commit_iter, err = local_repo.repo.Log(&git.LogOptions{
		All:        true,
		PathFilter: containsSynapseObjectName,
	})
	if err != nil {
		return nil, err
	}

	// lol
	for i, ok := 0, true; ok; ok, i = (err == nil && i < 20), i+1 {
		commit, err = commit_iter.Next()
		if err == nil {
			output = append(output, commit.Message)
		}
	}

	return output, nil
}

// checks out a specific branch/tag/commit in a local repo
func (local_repo *localRepo) checkout(object_type referenceType, object_id string) error {
	var options *git.CheckoutOptions
	var err error
	var tree *git.Worktree

	switch object_type {
	case BRANCH:
		options = &git.CheckoutOptions{
			Branch: gplumbing.NewRemoteReferenceName("origin", object_id),
		}
	case TAG:
		// STUB
	case COMMIT:
		options = &git.CheckoutOptions{
			Hash: gplumbing.NewHash(object_id),
		}
	}
	tree, err = local_repo.repo.Worktree()
	if err != nil {
		return err
	}

	err = tree.Checkout(options)
	if err != nil {
		return err
	}

	return nil
}
