db.Client.save({
  "_id": ObjectId("5113cc7835d9ec838be26223"),
  "redirect_uri": "http://localhost:8000/",
  "name": "oauth2js-client",
  "secret": "cae300a9fe5a4e6cecf4edb5eace3427aad3c4e4dff8663"
});

db.User.save({
  "_id": ObjectId("5113cd8035d9ec838be26224"),
  "email": "mail@example.com",
  "password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
});