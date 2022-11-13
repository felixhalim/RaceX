# RaceX

RaceX is a Static Log Analysis Tool that process Xdebug log and output possible interleaving PHP PDO SQL queries.

This tool enables developer to immediately view all possible interleaving queries for all tables and reason about possible race conditions.

## Getting Started

These instructions will get you a copy of the script up and running on your local machine for development and testing purposes.

### Downloading/ Cloning

To get the latest copy of the script, make sure that `git` is installed in your machine and run the command below

```bash
git clone https://github.com/felixhalim/RaceX.git
```

It will clone the latest copy of `RaceX`to your local machine. Then, navigate to the directory and you will see the files cloned.

```bash
cd ./RaceX
```

### Usage

To run the script, type the following command

```bash
./python main.py -f <xdebug_log.txt>
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
