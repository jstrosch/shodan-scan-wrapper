# Shodan Scan Wrapper
This Python3 script wraps the Shodan CLI *domain* and *scan* functionality. It accomplishes this by utilizing the *subprocess* module and gathering the results from STDOUT. This script requires that you install the Shodan CLI and initialize with your API key - [Shodan CLI](https://cli.shodan.io/).

The *host* command returns information about an IP address, such as open ports, running services, known vulnerabilities (CVEs), etc. However, if you want to scan via a domain you first need to resolve to an IP address. This script uses the *domain* command to retrieve DNS information, then parse out the IP from the A record before scanning.

Script takes two forms of input: a single domain (-d) or an input file with a single domain per line. The script will de-duplicate domains on the input file.

## Limitations

I primarily developed this to explore compromised infrastructure, which typically involves simple DNS configurations (ie a single A record). The script does not handle complex DNS results well.

## Example Input

Sample input file is provided - it is similar to output from [Emotet Droppers](https://github.com/jstrosch/emotet-droppers-fall2019)

![Example input](https://github.com/jstrosch/shodan-scan-wrapper/blob/master/example_input.png)

## Sample Output

Results from running the script against the input file.

![Example Output](https://github.com/jstrosch/shodan-scan-wrapper/blob/master/example_output.png)