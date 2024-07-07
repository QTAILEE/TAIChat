from werkzeug.security import check_password_hash

hashed_password_from_db = "scrypt:32768:8:1$nYz1Pew4X2OYx4fg$8d8f18cfd278a6d16b62987ed08e7dc33956a6fd6e89994e129552c3ceb35e8c3010f8d700a01177a24fe83ca62282ca9606f64ef90b0a4e5c67fcb70f7d4fd6"
provided_password = "1"

if check_password_hash(hashed_password_from_db, provided_password):
    print("Password is correct!")
else:
    print("Password is incorrect!")
