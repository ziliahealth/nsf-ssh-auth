Readme
======

A work in progress set of python click tools and helpers.

Hosted at <https://github.com/jraygauthier/nsf-py-click>.

For the moment, using <https://github.com/ingydotnet/git-subrepo> to share
this codebase across multiple dependant projects / repositories.

No formal python packaging at this time either, nor any planned short term.

Some example how to  use `git-subrepo`.

```bash
$ git subrepo init ./path/to/py/click -r git@github.com:jraygauthier/nsf-py-click.git -b master
$ git subrepo clone ./path/to/py/click -r git@github.com:jraygauthier/nsf-py-click.git -b master
$ git subrepo pull ./path/to/py/click
$ git subrepo commit ./path/to/py/click
$ git subrepo push ./path/to/py/click
```

Note that `pwd` should be at the root of the host repository when performing
these commands.
