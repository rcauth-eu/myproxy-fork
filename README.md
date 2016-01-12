# myproxy-fork

A fork of the **myproxy** project from the 
[CILogon](http://sourceforge.net/p/cilogon/code/HEAD/tree/trunk/edu.uiuc.ncsa/myproxy/) 
repository. This repository is structured into two branches:

## master 

The master branch is a clean copy of the remote repository mentioned above. Changes 
to the remote trunk have to be synced manually into the master branch in order to keep
this repository up to date. In order to keep track of versions, the revision number
of the remote trunk being synced is incuded into the commit messages.

## devel

The devel branch contains a modified version of the **myproxy** project hosted under the
master branch. The purpose of the branch was to implement:

* The [GetProxy](https://wiki.nikhef.nl/grid/OAuth_for_MyProxy_GetProxy_Endpoint) Endpoint
* Updated set of commands from the [MyProxy Protocol](http://grid.ncsa.illinois.edu/myproxy/protocol/) (GET, INFO, PUT, STORE)

If you are trying to build [Master Portal or VO Portal](https://github.com/ttomttom/aarc-portal/)
you should check out and build this devel branch first!

## Merging branches

In order to keep the devel branch up to date with new modification coming from the remote trunk
you have to:

1. Check out master branch `git checkout master`
2. Update the master branch with the latest changes from the remote trunk
3. Commit changes into master (include revision number of remote trunk in commit) `git commit -a -m '#rev'`
4. Check out devel branch `git checkout devel`
5. Merge the master branch into the devel branch `git merge master`
6. Solve any potential conflicts
6. Push changes `git push`



