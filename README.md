## Instruction for Ubuntu 22.04
Clone the repo via:

```
git clone https://github.com/Mahdi171/Unlinkable_PCS.git
```

And then change your directory to:
```
cd Unlinkable_PCS/
```

### Prerequisite Packages:
Install Docker and then run the following command to build the docker container:

```
sudo docker build -t ulpcs .
```
Now you can run the test files for any construction of your chose with any arbitrary attribute size. 


**Original PCS**

```
sudo docker run ulpcs python3 /app/PCS/test.py 3
```


**Generic ul-PCS**

```
sudo docker run ulpcs python3 /app/Generic/test.py 3
```


**RBAC ul-PCS**

```
sudo docker run ulpcs python3 /app/RBAC/test.py 5
```


**ul-PCS with Seperable Policies**

```
sudo docker run ulpcs python3 /app/SP/test.py 5
```
