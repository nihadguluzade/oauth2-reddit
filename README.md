# Reddit OAuth2 implementation using Spring Boot

OAuth2 support allows to use reddit to authenticate on non-reddit websites and applications.

As Reddit requires the *User-Agent* header to access the private APIs, it is necessary to write custom Token and UserInfo requests. This template uses the **Code** flow to allow the user to authenticate to the application.

To use this implementation you have to specify your *client_id*, *client_secret*, and *user-agent* (otherwise, error 429).

For more info see [wiki](https://github.com/reddit-archive/reddit/wiki/OAuth2).
