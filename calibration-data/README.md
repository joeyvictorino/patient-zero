# Pooled calibration data

`patient_zero/data/belief.yaml` holds guesses: how often a clean probe run means the control really holds, how much a self-attestation is worth. Nobody has measured these. This directory is where the measurements go.

## What to contribute

Before each probe run, record a forecast (`pz predict isolation 0.8 --by you`). After some have settled:

```
pz calibration --export my-org-2026-11.json
```

The file holds, for each settled prediction: the probe, the forecast, what `belief.yaml` forecast, whether the run came back clean, and the month. Names become `f1`, `f2`. The product name, notes, evidence and exact dates are left out. Read the file before you share it.

Open a pull request that adds the file here. Name it anything that does not identify you, if you would rather not be identified.

## What it is used for

```
pz calibration --pool calibration-data/
```

prints, per probe, how often runs came back clean and the Brier score of people and of `belief.yaml`. When there are enough settled predictions for a probe (at least 100), a pull request may change that probe's numbers in `belief.yaml`, citing this directory.

## What not to contribute

Anything from a system holding real patient data that you were not authorized to test, anything that names a customer, and made-up records. A fabricated file poisons the one dataset this project cannot get any other way.

There are no contributed files yet.
