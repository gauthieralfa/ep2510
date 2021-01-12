# Implementation of a Shared car Protocol 

### Step 1 : Registration 

Launch the server ServiceProvider.py and car1.py on 2 different terminals with : 

```sh
python3 ServiceProvider.py
```
and 
```sh
python3 car1.py
```
After that, on a new terminal, launch the client owner.py with : 
```sh
python3 owner.py
```
and write "registration" and press ENTER

### Step 2 : Reservation by the customer
```sh
python3 customer.py
```
and write "reservation" and press ENTER
 
### Step 3 : Session key created and o_check (MAC with masterkey) done by the owner
We assume that the owner receives a mail from the Service Provider and click on the link sending a specific information to the Service Provider. 
For that: 
```sh
python3 owner.py
```
and press ENTER

### Step 4 : Session key sent to the car

Done automatically 

### Step 5 : Access token and o_check sent to the customer
We also assume that the service provider sends a notification to the customer saying that he is ready to send to him the keys to open the car. 
```sh
$ python3 customer.py
```
and write "reception". 
### Step 6 : Open the car 
For this last step, with the application, the customer sends Access_token and o_check to the car. For that : 

```sh
$ python3 customer.py
```
and press ENTER

