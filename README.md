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

### Output Format

You will then see something like below

![image](https://user-images.githubusercontent.com/7411601/201530944-0242c883-4bb2-4a60-a19a-abf54a506037.png)

The output is composed of 3 parts; (1) basic info, (2) potential paths detected and (3) paths summary.

#### 1. Basic Info

![image](https://user-images.githubusercontent.com/7411601/201531137-f32981af-c6d2-4272-8c3b-31c9be3c463c.png)

In this part, the developer is able to view the basic information i.e. the distinct tables recorded in the log.

#### 2. Potential Paths Detected

![image](https://user-images.githubusercontent.com/7411601/201531142-15f54e04-046e-4463-a9b5-5715411cf776.png)

This part provides the developer complete view of all function calls to SQL queries grouped by the tables. It allows the developer to reason about possible race conditions based on all the possible paths/ interleaving queries.

#### 3. Paths Summary

![image](https://user-images.githubusercontent.com/7411601/201531152-7e5ef6f8-6c2f-4c02-bdb9-7c7883acd423.png)

The Paths Summary is similar to part (2) except that it is the compact version listing just the file and line number impacted.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
