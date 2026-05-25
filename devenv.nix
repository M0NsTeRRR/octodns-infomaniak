{
  pkgs,
  lib,
  config,
  ...
}:
{
  env = {
    INFOMANIAK_TOKEN = config.secretspec.secrets.INFOMANIAK_TOKEN or "";
  };

  packages = [
    pkgs.secretspec
  ];

  languages.python = {
    enable = true;
    version = lib.strings.trim (builtins.readFile ./.python-version);
    venv.enable = true;
    uv = {
      enable = true;
      sync = {
        enable = true;
        allExtras = true;
      };
    };
  };
}
