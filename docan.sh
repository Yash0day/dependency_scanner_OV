#!/bin/bash


output_dir="/home"
output_file="$output_dir/installed_packages.txt"

echo "[+] OS Version: $(cat /etc/issue | awk '{print $1, $2}')"
echo "$(cat /etc/issue | awk '{print $1, $2}')"  >> "$output_file" 2>/dev/null
echo "$(cat /etc/redhat-release | awk '{print $1, $2, $6}')" >> "$output_file" 2>/dev/null

#packages (Debian/Ubuntu)
echo "Installed packages (Debian/Ubuntu):" >> "$output_file"
dpkg -l | awk '/^ii/ {print $2, $3}' >> "$output_file" 

#packages (Red Hat/CentOS)
echo "Installed packages (Red Hat/CentOS):" >> "$output_file"
rpm -qa --queryformat '%{NAME} %{VERSION}\n' >> "$output_file" 2>/dev/null

#Python packages
echo "Installed Python packages:" >> "$output_file"
pip list >> "$output_file" 2>/dev/null

#Ruby gems
echo "Installed Ruby gems:" >> "$output_file"
gem list >> "$output_file" 2>/dev/null

#Node.js packages (npm)
echo "Installed Node.js packages (npm):" >> "$output_file"
npm list -g --depth=0 >> "$output_file" 2>/dev/null

#Node.js packages (Yarn)
echo "Installed Node.js packages (Yarn):" >> "$output_file"
yarn global list >> "$output_file" 2>/dev/null

#Go packages
echo "Installed Go packages:" >> "$output_file"
go list -m all >> "$output_file" 2>/dev/null

#Java packages
echo "Installed Java packages:" >> "$output_file"
java -version >> "$output_file" 2>/dev/null

#PHP modules
echo "Installed PHP modules:" >> "$output_file"
php -m >> "$output_file" 2>/dev/null

#Perl modules
echo "Installed Perl modules:" >> "$output_file"
perl -MExtUtils::Installed -e 'print join("\n", ExtUtils::Installed->new()->modules())' >> "$output_file" 2>/dev/null

#R packages
echo "Installed R packages:" >> "$output_file"
R -e 'installed.packages()' >> "$output_file" 2>/dev/null

#Lua packages
echo "Installed Lua packages:" >> "$output_file"
luarocks list >> "$output_file" 2>/dev/null

#Haskell packages
echo "Installed Haskell packages:" >> "$output_file"
ghc-pkg list >> "$output_file" 2>/dev/null

#Rust packages
echo "Installed Rust packages:" >> "$output_file"
cargo install --list >> "$output_file" 2>/dev/null

echo "[+] Package list saved to $output_file."
