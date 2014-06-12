goauth
=======

oAuth 2.0 Provider Implementation in GO!

A Server side component that implements oAuth Resource Owner Password Flow (ideal for first party apps).

It implements the following  services: <br>

	- sign up a new User 
	- get access and refresh tokens by posting username and password (grant_type = 'password')
	- get access token by posting refresh token ((grant_type = 'refresh_token') 
	- validate Access Token to gran access to data services.
	
It uses Hash with a Salt mechanism for storing encrypted passwords. Relies on GO 'crypt'<br>

examples:

	- POST http://localhost:8088/gomongo/signup
	       Body: {"username":"johnny1","password":"secrect12345",
	- POST http://localhost:8088/gomongo/auth/token 
	       Body: {"grant_type":"password","username":"johnny1","password":"secrect12345","client_id":"538e527aa5f3170fe9000001","client_secret":"jdshgfjhdgfjhgjhgj"}
	- POST http://localhost:8088/gomongo/auth/token
		   Body: {"grant_type":"refresh_token","client_id":"538e527aa5f3170fe9000001","client_secret":"jdshgfjhdgfjhgjhgj","refresh_token":"yZljXCbCtkg50x2K5ixgQVBam8QSSv0w4qIlUhyGGcBhvVoJi9ECQvFZK8hZhXbb"}
	- GET http://localhost:8088/gomongo/services/people/
			Header : Authorization : oAuth nlbXOQU2t3fTngNGfHJ9qH78CCk8tworwF6hyw7ZFUInuBzTLoRz6ZeuuWzsm1vO