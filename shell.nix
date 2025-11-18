{ pkgs ? import <nixpkgs> {} }:
(pkgs.buildFHSEnv {
  name = "pydev";
  targetPkgs = pkgs: [
    pkgs.python313
    pkgs.python313.pkgs.virtualenv
    pkgs.swaks
  ];

  profile = ''

    source .venv/bin/activate
  '';

  runScript = ''

    if [ ! -d .venv ]; then
      python -m venv .venv
      pip install -e .[dev]
    fi

    exec bash --login
  '';
}).env
