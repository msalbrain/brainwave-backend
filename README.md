
## Description

This is the backend template for brainwave.

## Quickstart
* create a copy of .env.example as .env and populate 

    ```bash
    cp .env.example .env
    ```



### Run the app in containers

* Clone the repo and navigate to the root folder.

* To run the app using Docker, make sure you've got [Docker][docker] installed on your
system. From the project's root dirctory, run:

    ```bash
    docker compose up -d
    ```

### Or, run the app locally

If you want to run the app locally, without using Docker, then:

* Clone the repo and navigate to the root folder.

* Create a virtual environment. Here I'm using Python's built-in venv in a Unix system.
Run:

    ```bash
    python3.11 -m venv .venv
    ```

* Activate the environment. Run:

    ```bash
    source .venv/bin/activate
    ```

* Go to the folder created by cookie-cutter (default is **fastapi-nano**).

* Install the dependencies. Run:

    ```bash
    pip install -r requirements.txt -r requirements-dev.txt
    ```

* Start the app. Run:

    ```bash
    uvicorn app.main:app --port 5000 --reload
    ```


### Check the APIs

* To play around with the APIs, go to the following link on your browser:

    ```
    http://localhost:5000/docs
    ```

    This will take you to an UI like below:

    ![Screenshot from 2020-06-21 22-15-18][screenshot_1]


## Folder structure

This shows the folder structure of the default template.

```
fastapi-nano
├── app                           # primary app folder
│   ├── apis                      # this houses all the API packages
│   │    └── api_a                 # api_a package
│   │        ├── __init__.py       # empty init file to make the api_a folder a package
│   │        ├── mainmod.py        # main module of api_a package
│   │        └── submod.py         # submodule of api_a package
│   ├── core                      # this is where the configs live
│   │   ├── auth.py               # authentication with OAuth2
│   │   ├── config.py             # sample config file
│   │   └── __init__.py           # empty init file to make the config folder a package
│   ├── __init__.py               # empty init file to make the app folder a package
│   ├── main.py                   # main file where the fastAPI() class is called
│   ├── routes                    # this is where all the routes live
│   │   └── views.py              # file containing the endpoints of api_a and api_b
│   └── tests                     # test package
│       ├── __init__.py           # empty init file to make the tests folder a package
│       ├── test_api.py           # integration testing the API responses
│       └── test_functions.py     # unit testing the underlying functions
├── dockerfiles                   # directory containing all the dockerfiles
├── .env                          # env file containing app variables
├── Caddyfile                     # simple reverse-proxy with caddy
├── docker-compose.yml            # docker-compose file
├── pyproject.toml                # pep-518 compliant config file
├── requrements-dev.in            # .in file to enlist the top-level dev requirements
├── requirements-dev.txt          # pinned dev dependencies
├── requirements.in               # .in file to enlist the top-level app dependencies
└── requirements.txt              # pinned app dependencies
```

In the above structure, `api_a` and `api_b` are the main packages where the code of the
APIs live and they are exposed by the endpoints defined in the `routes` folder. Here,
`api_a` and `api_b` have identical logic. Basically these are dummy APIs that take an
integer as input and return two random integers between zero and the input value. The
purpose of including two identical APIs in the template is to demonstrate how you can
decouple the logics of multiple APIs and then assemble their endpoints in the routes
directory. The following snippets show the logic behind the dummy APIs.

This is a dummy submodule that houses a function called `random_gen` which generates a
dictionary of random integers.

```python
# This a dummy module
# This gets called in the module_main.py file
from __future__ import annotations
import random


def rand_gen(num: int) -> dict[str, int]:
    num = int(num)
    d = {
        "seed": num,
        "random_first": random.randint(0, num),
        "random_second": random.randint(0, num),
    }
    return d
```

The `main_func` in the primary module calls the `rand_gen` function from the submodule.

```python
from __future__ import annotations
from app.api_a.submod import rand_gen


def main_func(num: int) -> dict[str, int]:
    d = rand_gen(num)
    return d
```

The endpoint is exposed like this:

```python
# app/routes/views.py
from __future__ import annotations
#... codes regarding authentication ...

# endpoint for api_a (api_b looks identical)
@router.get("/api_a/{num}", tags=["api_a"])
async def view_a(num: int, auth: Depends =Depends(get_current_user)) -> dict[str, int]:
    return main_func_a(num)
```

So hitting the API with a random integer will give you a response like the following:

```json
{
  "seed": 22,
  "random_first": 27,
  "random_second": 20
}
```

## Further modifications

* You can put your own API logics in the shape of `api_a` and `api_b` packages. You'll
have to add additional directories like `api_a` and `api_b` if you need more APIs.

* Then expose the APIs in the `routes/views.py` file. You may choose to create multiple
`views` files to organize your endpoints.

* This template uses OAuth2 based authentication and it's easy to change that. FastAPI
docs has a comprehensive list of the available [authentication][fastapi_security]
options and instructions on how to use them.

* You can change the application port in the `.env` file.

* During prod deployment, you might need to fiddle with the reverse-proxy rules in the
Caddyfile.

## Stack

* [Caddy][caddy]
* [Docker][docker]
* [FastAPI][fastapi]
* [Gunicorn][gunicorn]
* [Httpx][httpx]
* [Pip-tools](https://github.com/jazzband/pip-tools)
* [Pydantic](https://pydantic-docs.helpmanual.io/)
* [Pytest](https://docs.pytest.org/en/latest/)
* [Starlette](https://www.starlette.io/)
* [Uvicorn][uvicorn]
* [PyMongo][pymongo]

## Resources

* [Flask divisional folder structure][divisional_pattern]
* [Deploying APIs built with FastAPI](https://fastapi.tiangolo.com/deployment/)
* [Reverse proxying with Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

[caddy]: https://caddyserver.com/docs/
[cors]: https://fastapi.tiangolo.com/tutorial/cors/
[divisional_pattern]: https://exploreflask.com/en/latest/blueprints.html#divisional
[docker]: https://www.docker.com/
[fastapi]: https://fastapi.tiangolo.com/
[fastapi_security]: https://fastapi.tiangolo.com/tutorial/security/
[gunicorn]: https://gunicorn.org/
[httpx]: https://www.python-httpx.org/
[uvicorn]: https://uvicorn.org/
[pymongo]: https://pymongo.readthedocs.io/en/stable/

[screenshot_1]: https://user-images.githubusercontent.com/30027932/85229723-5b721880-b40d-11ea-8f03-de36c07a3ce5.png
[screenshot_2]: https://user-images.githubusercontent.com/30027932/85229725-5e6d0900-b40d-11ea-9c37-bbee546f84a8.png
[screenshot_3]: https://user-images.githubusercontent.com/30027932/85229729-6036cc80-b40d-11ea-877e-7421b927a849.png
[screenshot_4]: https://user-images.githubusercontent.com/30027932/85229992-fcad9e80-b40e-11ea-850d-9ca86259d463.png
[screenshot_5]: https://user-images.githubusercontent.com/30027932/85230016-25359880-b40f-11ea-9196-c46fd72a760c.png

<div align="center">
✨ 🍰 ✨
</div>
