# ReadMe

Cookie Information 
Cookies are small files of information that a web server generates and sends to a web browser. Web browsers store the cookies they receive for a predetermined period of time or for the length of a user's session on a website. They attach the relevant cookies to any future request the user makes of the web server.

The cookies used on the Internet are also called "HTTP cookies" and are sent using the HTTP protocol.

Where are cookies stored?
Web browsers store cookies in a designated file on users' devices. For example, the Google Chrome web browser stores all cookies in a file labeled "Cookies". Chrome users can view the cookies stored by the browser by following these steps:

Open developer tools
Click the "Application" tab
Click on "Cookies" in the left-side menu
What are cookies used for?
Cookies serve various purposes, including:

User sessions: Cookies help associate website activity with a specific user. A session cookie contains a unique string that matches a user session with relevant data and content for that user.
Types of Cookies
There are different types of cookies used on the Internet. Some of the most important types include:

Session cookies
A session cookie helps a website track a user's session. Session cookies are deleted after a user's session ends, such as when they log out of their account on a website or exit the website. Session cookies have no expiration date, and the browser deletes them once the session is over.

Persistent cookies
Persistent cookies remain in a user's browser for a predetermined length of time, which could be a day, a week, several months, or even years. Persistent cookies always contain an expiration date.

Authentication cookies
Authentication cookies help manage user sessions. They are generated when a user logs into an account via their browser and ensure that sensitive information is delivered to the correct user sessions by associating user account information with a cookie identifier string.

Tracking cookies
Tracking cookies are generated by tracking services. They record user activity, and browsers send this record to the associated tracking service the next time they load a website that uses that tracking service.

Zombie cookies
Zombie cookies regenerate after they are deleted. They create backup versions of themselves outside of a browser's typical cookie storage location and use these backups to reappear within a browser after deletion. Zombie cookies are sometimes used by unscrupulous ad networks and even by cyber attackers.

Structure of an HTTP Cookie
The structure of an HTTP cookie consists of several attributes that define its behavior and characteristics. Here's the general structure of an HTTP cookie:

Name: A unique identifier for the cookie. It is used to reference the cookie when sending it back to the server.
Value: The value associated with the cookie. It can contain any arbitrary data that the server wants to store on the client's browser.
Domain: The domain name associated with the cookie. It specifies the domain within which the cookie is valid. The cookie will be sent in subsequent requests to this domain and its subdomains.
Path: The path within the domain for which the cookie is valid. It specifies the URL path that must exist in the requested URL for the cookie to be sent.
Expiration/Max-Age: The expiry date and time of the cookie. It determines how long the cookie will be stored on the client's browser. If not specified, the cookie is considered a session cookie and will be deleted when the browser session ends.
Secure: A flag indicating whether the cookie should only be sent over HTTPS connections.
HttpOnly: A flag indicating whether the cookie is accessible only through HTTP(S) requests and cannot be accessed by client-side scripts. This helps mitigate certain types of cross-site scripting (XSS) attacks.
SameSite: A flag that controls how the cookie is sent in cross-origin requests. It helps mitigate cross-site request forgery (CSRF) attacks. Possible values are "Strict," "Lax," or "None."
This information provides a basic understanding of cookies, their types, and their structure in the context of web browsing.
