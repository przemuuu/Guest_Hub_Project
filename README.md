# GuestHub Project - Airbnb clone
### MongoDB, Python (Flask) backend, JavaScript (Vite + React) frontend
#### Authors: Jakub Białecki, Przemysław Popowski, Jakub Worek

## How to launch project?
To run the application correctly, follow these steps:
1. Open the **upload_service** folder in the terminal.
2. Run the command `npm install`.
3. Run the command `node index.js`.
4. Open the **backend** folder in the terminal.
5. Install the required Python libraries.
6. Run `app.py`.
7. Open the **frontend** folder in the terminal.
8. Run the command `npm install`.
9. Run the command `npm run dev`.

And now you can enjoy the working application at the link `http://localhost:5173` :D

## Introductory comment:
The application was designed with modularity and easy scalability in mind.
The use of MongoDB with the MongoEngine ORM simplifies data handling, while Flask, along with extensions such as Flask-JWT-Extended and Flask-Bcrypt, provides a solid foundation for security.

## Data model - database design:
1. Model "User" - User
- `name` - user's full name - string
- `email` - email for login - email, unique
- `password` - password for login - string

2. "Place" Model - Accommodation Place
- `owner` - reference to the user who owns the place - User
- `title` - name of the place - string
- `address` - address of the place - string
- `photos` - photos of the place - list[string]
- `description` - description of the place - string
- `perks` - list of amenities or advantages offered by the place - list[string]
- `extraInfo` - additional information about the place - string
- `checkIn` - check-in time - int
- `checkOut` - check-out time - int
- `maxGuests` - maximum number of guests the place can accommodate - int
- `price` - price per night - float

3. "Booking" Model - Booking
- `place` - reference to the booked place - Place
- `user` - reference to the user who made the booking - User
- `checkIn` - check-in date - date
- `checkOut` - check-out date - date
- `name` - full name of the person making the booking - string
- `phone` - phone number of the person making the booking - string
- `price` - amount paid - float
- `numberOfGuests` - number of guests during the stay - int

## Description of database operations:
1. Operation `create_user()` -> Creating a user profile and adding it to the database
```python
@app.route('/test/user', methods=['POST'])
def create_user():
    try:
        # Fetch data from the request
        name = request.json['name']
        email = request.json['email']
        password = request.json['password']

        # Create a new user
        user = User(name=name, email=email, password=password)
        user.save()  # Saving to the database

        # Return user data (excluding the password for security)
        return jsonify({
            'name': user.name,
            'email': user.email
        }), 200
    except Exception as e: 
        return jsonify({'error': str(e)}), 400
```

2. Operation `register_user()` -> Registering a new user and adding them to the database
```python
@app.route('/api/register', methods=['POST'])
def register_user():
    try:
        # Fetch data from the request
        name = request.json.get('name')
        email = request.json.get('email')
        password = request.json.get('password')

        # Hashing password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user
        user = User(name=name, email=email, password=hashed_password)
        user.save()  # Saving to the database

        # Return user data (excluding the password for security)
        return jsonify({
            'name': user.name,
            'email': user.email
        }), 201

    except ValidationError as ve:
        # Handling validation errors (e.g., missing fields)
        logging.error(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except NotUniqueError:
        # Handling an attempt to create a user with an already existing email address
        logging.error("Attempt to create a user with a duplicate email")
        return jsonify({'error': 'This email is already used.'}), 400
    except Exception as e:
        # General error handling
        logging.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
```

3. Operation `login()` -> User login and data verification
```python
@app.route('/api/login', methods=['POST'])
def login():
    try:
        # Fetch data from the request
        email = request.json.get('email')
        password = request.json.get('password')

        # Finding a user with the provided email
        user = User.objects.get(email=email)

        # Password verification
        if bcrypt.check_password_hash(user.password, password):
            # Creating a 'token' cookie
            access_token = create_access_token(identity=str(user.id), additional_claims={"email": user.email})
            response = jsonify(name=user.name, email=user.email, token = access_token)
            return response
        else:
            # Incorrect login credentials
            return jsonify({"error": "Invalid credentials"}), 401  
    except DoesNotExist:
        # User does not exist
        return jsonify({"error": "User not found"}), 404
    except ValidationError:
        # Invalid input data
        return jsonify({"error": "Invalid data"}), 400
    except Exception as e:
        # Other server error
        return jsonify({"error": str(e)}), 500
```

4. Operation `get_user_profile()` -> Returns the profile of the currently logged-in user

```python
@app.route('/api/profile', methods=['GET'])
@jwt_required()  # Requires a valid JWT token in the request headers
def get_user_profile():
    try:
        user_id = get_jwt_identity()  # Retrieves the user ID from the JWT token
        user = User.objects.get(id=user_id)  # Use get for precise lookup and error if the user does not exist

        # Return user data in JSON format
        return jsonify({
            "name": user.name,
            "email": user.email,
            "_id": str(user.id)  # Convert ObjectId to string
        })

    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404  # User does not exist
    except ValidationError:
        return jsonify({"error": "Invalid data"}), 400  # Invalid input data
    except Exception as e:
        # Log the error for further analysis
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error"}), 500  # Other server error
```

5. Operation `logout()` -> Logs out the currently logged-in user
```python
@app.route('/api/logout', methods=['POST'])
def logout():
    # Create a response that will remove the 'token' cookie
    response = make_response(jsonify(True))  # Return a JSON with a True value
    response.set_cookie('token', '', expires=0)  # Remove the cookie by setting the expiration date to 0
    return response
```

6. Operation `send_email()` -> Sends an email to the user confirming the reservation
```python
@app.route('/api/notify', methods=['POST'])
@jwt_required()
def send_email():
    try:
        # Retrieving data from the request
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        user_email = user.email
        message = request.json.get('message')

        # Creating the message structure
        msg = Message(  subject = 'GuestHub Notification', 
                        sender='guesthubnotify@fastmail.com',
                        recipients=[user_email],
                        body=message)

        # Sending the email
        mail.send(msg)
        return jsonify('Email sent'), 200
    
    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404  # User does not exist
    except ValidationError:
        return jsonify({"error": "Invalid data"}), 400  # Invalid input data
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Other server error
```

7. Operation `add_place()` -> Adds a new place
```python
@app.route('/api/places', methods=['POST'])
@jwt_required()
def add_place():
    user_id = get_jwt_identity()  # Retrieves the user ID from the JWT token
    data = request.json

    # Creating the place structure
    place = Place(
        owner=user_id,
        title=data['title'],
        address=data['address'],
        photos=data.get('addedPhotos', []),
        description=data['description'],
        perks=data.get('perks', []),
        extraInfo=data.get('extraInfo', ''),
        checkIn=data['checkIn'],
        checkOut=data['checkOut'],
        maxGuests=data['maxGuests'],
        price=data['price']
    )
    # Saving it to the database
    place.save()
    return jsonify(place=place.to_json())
```

8. Operation `get_user_places()` -> Displays places owned by the currently logged-in user
```python
@app.route('/api/user-places', methods=['GET'])
@jwt_required()
def get_user_places():
    # Retrieves the user ID from the JWT token
    user_id = get_jwt_identity()

    # Finding places owned by the user
    places = Place.objects(owner=user_id).all()  
    json_data = places.to_json()
    dicts = json.loads(json_data)
    for i in range(len(dicts)):
        dicts[i]['_id'] = dicts[i]['_id']['$oid']
    return dicts
```

9. Operation `get_place(id)` -> Returns the place with the specified ID
```python
@app.route('/api/places/<id>', methods=['GET'])
def get_place(id): 
    try:
        place = Place.objects.get(id=id)
        print(place)
        json_data = place.to_json()
        print(json_data)
        dicts = json.loads(json_data)
        print(dicts)
        dicts['_id'] = dicts['_id']['$oid']
        print(dicts)
        return dicts, 200
    except DoesNotExist:
        return jsonify({"error": "Place not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

```

10. Operation `update_place()` -> Updates data about the currently edited place
```python
@app.route('/api/places', methods=['PUT'])
@jwt_required()
def update_place():
    # Retrieves the user ID from the JWT token
    user_id = get_jwt_identity()
    data = request.json
    try:
        # Updating the data of the current place
        place = Place.objects.get(id=data['id'])
        if str(place.owner.id) == user_id:
            place.update(
                title=data.get('title', place.title),
                address=data.get('address', place.address),
                photos=data.get('addedPhotos', place.photos),
                description=data.get('description', place.description),
                perks=data.get('perks', place.perks),
                extraInfo=data.get('extraInfo', place.extraInfo),
                checkIn=data.get('checkIn', place.checkIn),
                checkOut=data.get('checkOut', place.checkOut),
                maxGuests=data.get('maxGuests', place.maxGuests),
                price=data.get('price', place.price)
            )
            return jsonify('ok'), 200
        else:
            return jsonify({'error': 'Unauthorized access'}), 403
    except Place.DoesNotExist:
        return jsonify({'error': 'Place not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

11. Operation `get_places()` -> Returns all available places
```python
@app.route('/api/places', methods=['GET'])
def get_places():
    places = Place.objects().all()  # Retrieve all documents in the Place collection
    json_data = places.to_json()
    dicts = json.loads(json_data)
    for i in range(len(dicts)):
        dicts[i]['_id'] = dicts[i]['_id']['$oid']
    return dicts, 200
```

12. Operation `create_booking()` -> Creates a new booking and adds it to the database
```python
@app.route('/api/bookings', methods=['POST'])
@jwt_required()
def create_booking():
    # Retrieves the user ID from the JWT token
    user_id = get_jwt_identity()

    # Retrieving data from the request
    data = request.get_json()
    place_id = data['place']
    checkIn = datetime.datetime.strptime(data['checkIn'], '%Y-%m-%d')
    checkOut = datetime.datetime.strptime(data['checkOut'], '%Y-%m-%d')
    numberOfGuests = int(data['numberOfGuests'])

    try:
        # Verifying the availability of the accommodation at the selected place
        place = Place.objects.get(id=place_id)
        if place.maxGuests < numberOfGuests:
            return jsonify('too many guests'), 422
            
        overlapping_bookings = Booking.objects(
            place=place_id,
            checkIn__lte=checkOut,
            checkOut__gte=checkIn
        )
        if overlapping_bookings:
            return jsonify('place is not available'), 422

        # Creating the booking and adding it to the database
        booking = Booking(
            place=place,
            checkIn=checkIn,
            checkOut=checkOut,
            numberOfGuests=numberOfGuests,
            name=data['name'],
            phone=data['phone'],
            price=data['price'],
            user=user_id
        )
        booking.save()

        dict = json.loads(booking.to_json())
        dict['_id'] = dict['_id']['$oid']
        dict['place'] = dict['place']['$oid']
        dict['user'] = dict['user']['$oid']
        dict['checkIn'] = dict['checkIn']['$date']
        dict['checkOut'] = dict['checkOut']['$date']
        dict['place'] = json.loads(Place.objects().get(id=dict['place']).to_json())
        dict['user'] = json.loads(User.objects().get(id=dict['user']).to_json())

        return dict, 201

    except DoesNotExist:
        return jsonify({'error': 'Place not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

13. Operation `get_bookings()` -> Returns a list of bookings for the current user
```python
@app.route('/api/bookings', methods=['GET'])
@jwt_required()
def get_bookings():
    try:
        # Retrieving data from the request
        user_id = get_jwt_identity()
        bookings = Booking.objects(user=user_id).all()
        json_data = bookings.to_json()
        dicts = json.loads(json_data)

        # Returning the bookings
        for i in range(len(dicts)):
            dicts[i]['_id'] = dicts[i]['_id']['$oid']
            dicts[i]['place'] = dicts[i]['place']['$oid']
            dicts[i]['user'] = dicts[i]['user']['$oid']
            dicts[i]['checkIn'] = dicts[i]['checkIn']['$date']
            dicts[i]['checkOut'] = dicts[i]['checkOut']['$date']
            dicts[i]['place'] = json.loads(Place.objects().get(id=dicts[i]['place']).to_json())
            dicts[i]['user'] = json.loads(User.objects().get(id=dicts[i]['user']).to_json())
        return dicts
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

14. Operation `detailed_bookings()` -> Detailed report of all bookings
```python
@app.route('/api/report/detailed_bookings', methods=['GET'])
def detailed_bookings():
    try:
        bookings = Booking.objects().all()
        detailed_report = []

        for booking in bookings:
            user = User.objects.get(id=booking.user.id)
            place = Place.objects.get(id=booking.place.id)

            detailed_report.append({
                'booking_id': str(booking.id),
                'user': {
                    'name': user.name,
                    'email': user.email
                },
                'place': {
                    'title': place.title,
                    'address': place.address
                },
                'check_in': booking.checkIn,
                'check_out': booking.checkOut,
                'price': booking.price
            })
        return detailed_report
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

15. Operation `user_activity_report()` -> Report of user activity within a specified time range
```python
@app.route('/api/report/user_activity', methods=['GET'])
@jwt_required()
def user_activity_report():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    activities = []

    bookings = Booking.objects(checkIn__gte=start_date, checkOut__lte=end_date).all()
    for booking in bookings:
        activities.append({
            'user_id': str(booking.user.id),
            'activity': 'booking',
            'date': booking.checkIn
        })

    users = User.objects(registeredOn__gte=start_date, registeredOn__lte=end_date).all()
    for user in users:
        activities.append({
            'user_id': str(user.id),
            'activity': 'registration',
            'date': user.registeredOn
        })

    users = User.objects(dateOfLogin__gte=start_date, dateOfLogin__lte=end_date).all()
    for user in users:
        activities.append({
            'user_id': str(user.id),
            'activity': 'login',
            'date': user.dateOfLogin
        })

    return activities
```

16. Operation `financial_report()` -> Financial report of individual places over the last year, divided by months
```python
@app.route('/api/report/financial', methods=['GET'])
def financial_report():
    year = request.args.get('year')
    monthly_earnings = []

    for month in range(1, 13):
        bookings = Booking.objects(
            checkIn__year=year, checkIn__month=month
        )
        for booking in bookings:
            monthly_earnings.append({
                'month': month,
                'total_earnings': booking.sum('price'),
                'booking_title': booking.booking_title
            })

    return monthly_earnings
```

17. Operation `users_total_spending()` -> Report returning the total amount of money spent by individual users
```python
@app.route('/api/report/users_total_spending_', methods=['GET'])
def users_total_spending():
    try:
        users = User.objects().all()
        user_total_spending = []
        for user in users:
            bookings_spending = Booking.objects(user_id = user.id).sum('price')
            user_total_spending.append({
                'user_id': user.id,
                'user_email': user.email,
                'bookings_spending':bookings_spending
            })

        return user_activity_report, 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

## Demonstration of the capabilities of technologies used in the project:
1. `Flask`: Serves as a web framework for creating and handling APIs.
2. `Flask-Bcrypt`: Used for hashing passwords to enhance user security.
3. `Flask-JWT-Extended`: For handling JWT tokens, ensuring secure authentication and authorization.
4. `Flask-CORS`: Enables CORS (Cross-Origin Resource Sharing) support, which is essential for applications running on different domains.
5. `MongoEngine`: Acts as an ORM (Object-Relational Mapping) for MongoDB, allowing more convenient database operations.
6. `Flask-Mail`: For sending email notifications.
7. `dotenv`: For loading environment variables from the `.env` file.

## Discussion of applied techniques and methods:
1. `JWT`: JWT tokens provide secure and scalable authentication. They are easy to store on the client side (e.g., in cookies or localStorage).
2. `ORM (MongoEngine)`: ORM simplifies working with the database by allowing CRUD operations using Python objects instead of direct database queries.
3. `Password Hashing`: Using bcrypt for password hashing ensures a high level of security, protecting against brute-force attacks.

---
### 4th semester, Computer Science, AGH University of Krakow
