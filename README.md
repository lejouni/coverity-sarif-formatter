# coverity-sarif-formatter
This action will create a sarif format report from json-v10 output.

## Available Options
| Option name | Description | Default value | Required |
|----------|----------|---------|----------|
| log_level | Logging level | DEBUG | false |
| inputfile | Filename with path which will contain the local scan findings (Coverity Analysis results should be provided in the \"v10\" JSON format produced by the --json-output-v10 option of the cov-format-errors command or the cov-run-desktop command.), example /tmp/coverityFindings.json | - | true |
| outputfile | Filename with path where it will be created, example /tmp/coverity_results.sarif.json | ${{github.workspace}}/coverity_results.sarif.json | false |

## Usage examples
Create Sarif -format results from given Coverity Analysis results in json-v10.
```yaml
    - name: Formating json-v10 to Sarif
      uses: lejouni/coverity-sarif-formatter@v0.1.2
      with:
        log_level: DEBUG
        inputfile: ${{github.workspace}}/coverity_results.json
        outputfile: ${{github.workspace}}/coverity_results.sarif.json
```