# Releasing Toolwrit

Everything here has been rehearsed except the four steps that need an account
someone owns. Those are marked **[you]**; the rest is already done or is a
command you can paste.

## Layout

The project is two packages that share one hash chain, so they are released
together from one repository:

```
toolwrit/                 <- repository root
├── .github/workflows/ci.yml
├── js/                     <- TypeScript package, published to npm as `toolwrit`
└── python/                 <- Python package, published to PyPI as `toolwrit`
```

Both publish under the name `toolwrit`; both install a CLI called `toolwrit`.
The package name and the command are the same word on both sides — there is no
need for the shorter-name-plus-different-binary split the project used before.

**[you]** confirm `toolwrit` is free on npm and on PyPI immediately before
publishing. It was chosen because it is not taken and does not collide with
anything in this category, but npm does not reserve a name until you push. (On
PyPI the pending-publisher step below claims it without publishing — do that
one first.)

## Before publishing anything

```sh
cd js       && npm ci && npm run typecheck && npm test && npm run build
cd ../python  && python -m pytest -q
```

Both suites must be green. CI runs these plus a cross-language job that proves
a chain written by one implementation verifies with the other and that the
entry hashes are equal — if that job ever fails, do not publish; the two
implementations have drifted and every claim about chain compatibility is void.

## How publishing works here

`.github/workflows/release.yml` publishes both packages from one tag. It stores
no tokens: both registries support OIDC *trusted publishing*, where the registry
verifies the workflow identity — this repository, this workflow file — and mints
a credential that lives for one run. There is no long-lived secret to leak, and
a fork cannot publish.

The two registries differ in one way that decides the order below: **PyPI lets
you register a publisher before the project exists; npm does not.**

## PyPI — do this first, because it also reserves the name

**[you]** at <https://pypi.org/manage/account/publishing/>, under *Add a new
pending publisher*:

| field | value |
|---|---|
| PyPI Project Name | `toolwrit` |
| Owner | `emektor` |
| Repository name | `toolwrit` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

A *pending* publisher is one for a project that does not exist yet, and creating
it **claims the name `toolwrit` on PyPI**. Worth doing before anything else: the
name is the one part of this that somebody else could take. Nothing further is
needed — the first tag publishes it.

## npm — one manual publish, then it is automated too

npm only accepts a trusted publisher on a package that already exists, so
version 0.1.0 goes up from a terminal once:

```sh
# [you] npm login   (2FA is fine; publishing will prompt)
npm install -g npm@latest   # trusted publishing needs npm >= 11.5.1
cd js
npm pack --dry-run          # read the file list once, on purpose
npm publish --access public # prepublishOnly runs the tests and build first
```

Then **[you]** on <https://www.npmjs.com/package/toolwrit> → *Settings* →
*Trusted publisher*: owner `emektor`, repository `toolwrit`, workflow
`release.yml`, environment `npm`. Every version after 0.1.0 comes from the
workflow, and the token used above can be revoked.

npm matches the package to the repository through `repository.url` in
`package.json`. It is already `git+https://github.com/emektor/toolwrit.git` — if
the repository is ever renamed or transferred, that field has to move with it or
trusted publishing stops working.

## GitHub environments

The two publish jobs run in environments named `npm` and `pypi`. **[you]**
create them under *Settings → Environments*. They can be empty; they exist so
each registry can pin its publisher to one environment, and so a required
reviewer can be added later if a human gate before a release is ever wanted.

## Cutting a release

```sh
# bump both files to the same number
git commit -am "Release v0.1.1" && git tag v0.1.1
git push && git push --tags
```

The workflow refuses to publish if the tag and the two version fields disagree,
runs both suites on the tagged commit, publishes npm and PyPI, then cuts the
GitHub release. Verify the way a stranger would:

```sh
cd "$(mktemp -d)" && npm init -y && npm install toolwrit
./node_modules/.bin/toolwrit --version

python -m venv /tmp/v && /tmp/v/bin/pip install toolwrit
/tmp/v/bin/toolwrit --help
```

## The landing page

No domain. The launch links to this repository, which is where a reader wants to
end up anyway, and a hyphenated or half-remembered domain is worth less than
nothing. `site/index.html` is one self-contained file — serve it from GitHub
Pages by pointing Settings -> Pages at the branch, or drop it on any host later
if a domain is ever worth buying.

## Versioning

`0.1.0` on both. Keep the two versions identical: they share a wire format, and
a user pairing npm 0.2 with PyPI 0.1 must be able to tell at a glance that they
have mismatched halves.

Anything that changes what goes into an audit entry is a breaking change for
the chain even when the API is untouched, because logs written by the old
version will no longer match the new one's shape. Bump accordingly and say so
in the release notes.

## Where the human still decides

Publishing is automated; *choosing to publish* is not. The tag is the decision,
and it is made by a person — the workflow only fires on `v*`. The `npm` and
`pypi` environments are the place to add a required reviewer if that one gate
should become two.
