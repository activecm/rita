# Configuration


RITA's behavior and performance can be fine-tuned using a configuration file. This configuration file allows you to adjust various settings, including scoring parameters that affect how different types of network activities are evaluated.

## Location of the Configuration File
The default configuration file is located [here](/default-config.hjson). 

When RITA is installed, the config file is located at `/etc/rita/config.hjson`.

You can specify a different configuration file location using the `-c` or `--config` flag when running RITA:

```bash
./rita -c /path/to/your/custom/config.conf <command> <flags>
```

## Fine-Tuning the Scoring
The configuration file includes various parameters that control the scoring mechanism used by RITA. Adjusting these parameters can help you customize how different types of network threats are evaluated and scored.

Below are some of the key sections and parameters you can adjust:

### Scoring
This section defines scoring parameters for each type of network threat. Please refer to the [default configuration file](/default-config.hjson) for a concise summary of each parameter and how it affects the detection and scoring of different threat types. This will provide a comprehensive overview of the available configuration options and how to customize them to meet your specific needs.  Below is an explanation of some common parameters that apply to multiple threat types.

#### Score Thresholds
The score_thresholds section defines the thresholds for categorizing the severity of network activities based on their scores. Each scoring category (e.g., beacon, long_connection) has its own thresholds for determining whether an activity falls into the base, low, medium, or high severity levels.

Example:

```yaml
scoring: {
    beacon: {
        ...
        score_thresholds: {
            base: 50,
            low: 70,
            medium: 90,
            high: 100
        }
    },
    ...
}
```
In this example, a beacon score of:

Less than 50 is considered below the base threshold.
Between 50 and 69 is considered low.
Between 70 and 89 is considered medium.
90 and above is considered high.

#### Impact
The impact sections in the scoring configuration determine the severity category for specific types of activities. For example, any activity flagged as a strobe or a threat intel hit can be placed in the high category regardless of their individual scores.

Example:

```yaml
scoring: {
    ...
    strobe_impact: {
        category: "high" // any strobes will be placed in the high category
    },
    threat_intel_impact: {
        category: "high" // any threat intel hits will be placed in the high category
    }
}
```
In this example, any strobe or threat intel hit will be automatically categorized as high severity.

*Note that the category cannot be set to "critical".*

### Score Modification
Scores for detected threats can be modified (increased or decreased) based on other behaviors detected. 

The configuration for modifiers is in the `modifiers` object within the configuration file.

Some modifiers only apply if a certain threshold is met, while other modifiers either apply or do not apply. For example:

#### Modifier with thresholds:

The Prevalence modifier increases the score of a threat by `prevalence_score_increase` (ex: `0.15` (+15%)) if the prevalence of the external host is less than or equal to the `prevalence_increase_threshold` (ex: `0.02` (2%)). 

Inversely, the prevalence modifier also has a score decrease and a decrease threshold, where the threat score will decrease by `prevalence_score_decrease` if the prevalence is greater than or equal to the `prevalence_decrease_threshold`.

#### Modifier without thresholds:

The Missing Host Header modifier increases the threat score by `missing_host_count_score_increase` if the connection had no host header set.

### Applying Configuration Changes
After making changes to the configuration file, save the file and re-run RITA to apply the changes:

```bash
./rita -c /path/to/your/config/rita.conf <command> <flags>
```
To apply these changes immediately, the dataset will need to be destroyed and reimported. To do this, use the `--rebuild` flag.

The changes will not *fully* propogate a rolling dataset until an import is made 24 hours after the config was changed.

By adjusting these configuration parameters, you can fine-tune RITA's scoring to better match your network's characteristics and security policies.