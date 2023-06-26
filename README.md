## Instruction for Ubuntu 22.04
Clone the repo and then run:
```
cd /myproject
```

### Prerequisite Packages:
Install Docker and then run the following command to build the docker container:

```
sudo docker build -t ulpcs .
```
Now you can run the test files for any construction of your chose with any arbitrary attribute size. 


**Original PCS**

```
sudo docker run ulpcs python3 /app/PCS/test.py 2
```


**Generic ul-PCS**

```
sudo docker run ulpcs python3 /app/Generic/test.py 2
```


**RBAC ul-PCS**

```
sudo docker run ulpcs python3 /app/RBAC/test.py 10 
```


**ul-PCS with Seperable Policies**

```
sudo docker run ulpcs python3 /app/SP/test.py 10
```
