{ lib
, buildPythonPackage
, mypy
, pytest
, flake8
, ipython
, click
, pyyaml
, nix-gitignore
, nsf-shc-nix-lib
}:

buildPythonPackage rec  {
  pname = "nsf-ssh-auth-cli";
  version = "0.1.0";
  src = nix-gitignore.gitignoreSourcePure ../.gitignore ./.;
  buildInputs = [ ];

  doCheck = false;

  checkInputs = [
    mypy
    pytest
    flake8
  ];

  checkPhase = ''
    mypy .
    pytest .
    flake8
  '';

  propagatedBuildInputs = [
    click
    pyyaml
  ];

  postInstall = with nsf-shc-nix-lib; ''
    buildPythonPath "$out"
    ${nsfShC.pkg.installClickExesBashCompletion [
      "nsf-ssh-auth-dir"
    ]}
  '';
}
