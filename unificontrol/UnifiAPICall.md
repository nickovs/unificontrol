# Implementing API calls

The  main `UnifiClient` class implements the more than 100 API calls to read and change settings on the controller. The vast majority of these calls map directly to a single https access to a specific endpoint on the Unifi controller web service. In order to avoid a great deal of repetition and [boilerplate code](https://en.wikipedia.org/wiki/Boilerplate_code) each of these calls is created using [metaprogramming](https://en.wikipedia.org/wiki/Metaprogramming); rather than writing code to implement each function the functions are describedat a high level and the details are created when the class is first loaded.

There are several advantages to using metaprogramming in this stiuation. Chief among these are:
* The nature and the intent of the function are easier to see since there is less extraneous 
