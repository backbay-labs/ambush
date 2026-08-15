#!/usr/bin/env bash

# Shared byte-safe inventory and rendering helpers for the detector experiment
# fixture generator and freshness gate. Callers must enable `set -o pipefail`.

fixture_inventory_write() {
  local root="$1"
  local destination="$2"

  git -C "$root" ls-files -z -c -o --exclude-standard -- experiments \
    | LC_ALL=C /usr/bin/perl -0 -e '
        use strict;
        use warnings;
        my @paths;
        while (defined(my $path = <STDIN>)) {
          $path =~ s/\0\z//;
          push @paths, $path if $path =~ /\.(?:yaml|yml)\z/;
        }
        for my $path (sort { $a cmp $b } @paths) {
          print $path, "\0";
        }
      ' >"$destination"
}

fixture_directory_inventory_write() {
  local directory="$1"
  local destination="$2"

  LC_ALL=C /usr/bin/perl -e '
    use strict;
    use warnings;
    my $directory = shift @ARGV;
    opendir(my $handle, $directory) or die "cannot enumerate generated fixture directory\n";
    my @names = sort { $a cmp $b } grep { $_ ne "." && $_ ne ".." } readdir($handle);
    closedir($handle) or die "cannot close generated fixture directory\n";
    for my $name (@names) {
      print $name, "\0";
    }
  ' "$directory" >"$destination"
}

fixture_display() {
  printf '%s' "$1" | LC_ALL=C /usr/bin/perl -e '
    use strict;
    use warnings;
    local $/;
    my $value = <STDIN> // "";
    $value =~ s/([\\"])/\\$1/g;
    $value =~ s/\n/\\n/g;
    $value =~ s/\r/\\r/g;
    $value =~ s/\t/\\t/g;
    $value =~ s/([\x00-\x1f\x7f])/sprintf("\\u%04x", ord($1))/ge;
    $value =~ s/([\x80-\xff])/sprintf("\\u00%02x", ord($1))/ge;
    print "\"", $value, "\"";
  '
}

fixture_display_stream() {
  LC_ALL=C /usr/bin/perl -e '
    use strict;
    use warnings;
    local $/;
    my $value = <STDIN> // "";
    $value =~ s/([\\"])/\\$1/g;
    $value =~ s/\n/\\n/g;
    $value =~ s/\r/\\r/g;
    $value =~ s/\t/\\t/g;
    $value =~ s/([\x00-\x1f\x7f])/sprintf("\\u%04x", ord($1))/ge;
    $value =~ s/([\x80-\xff])/sprintf("\\u00%02x", ord($1))/ge;
    print "\"", $value, "\"";
  '
}

fixture_require_direct_path() {
  local path="$1"
  case "$path" in
    experiments/*/*)
      echo "nested experiment fixture is outside experiments/*.{yaml,yml}: $(fixture_display "$path")" >&2
      return 1
      ;;
    experiments/*.yaml|experiments/*.yml)
      return 0
      ;;
    *)
      echo "invalid experiment fixture inventory path: $(fixture_display "$path")" >&2
      return 1
      ;;
  esac
}
