from flask import Flask, request, render_template, render_template_string, make_response, Response
from markupsafe import Markup
from types import SimpleNamespace

app = Flask(__name__)


def render(*args, **kwargs):
    return ""


def HttpResponse(value):
    return value


def HttpResponseBadRequest(value):
    return value


def HttpResponseNotFound(value):
    return value


def HttpResponseForbidden(value):
    return value


def HttpResponseRedirect(value):
    return value


def TemplateResponse(*args, **kwargs):
    return ""


def HTMLResponse(value):
    return value


def PlainTextResponse(value):
    return value


def CustomResponse(value):
    return value


def CustomRender(value):
    return value


class Jinja2Templates:
    @staticmethod
    def TemplateResponse(*args, **kwargs):
        return ""


templates = SimpleNamespace(TemplateResponse=TemplateResponse)
django = SimpleNamespace(
    shortcuts=SimpleNamespace(render=render),
    http=SimpleNamespace(
        HttpResponse=HttpResponse,
        HttpResponseBadRequest=HttpResponseBadRequest,
        HttpResponseNotFound=HttpResponseNotFound,
        HttpResponseForbidden=HttpResponseForbidden,
        HttpResponseRedirect=HttpResponseRedirect,
    ),
)
fastapi = SimpleNamespace(
    responses=SimpleNamespace(
        HTMLResponse=HTMLResponse,
        PlainTextResponse=PlainTextResponse,
    )
)
flask = SimpleNamespace(
    render_template=render_template,
    render_template_string=render_template_string,
    make_response=make_response,
    Response=Response,
)
markupsafe = SimpleNamespace(Markup=Markup)


# CASE 1
@app.route("/case1")
def case1():
    v = request.args.get("q")
    return v


# CASE 2
@app.route("/case2")
def case2():
    v = request.args["q"]
    return f"<div>{v}</div>"


# CASE 3
@app.route("/case3")
def case3():
    v = request.form.get("q")
    return render_template(v)


# CASE 4
@app.route("/case4")
def case4():
    v = request.form["q"]
    return render_template_string(v)


# CASE 5
@app.route("/case5")
def case5():
    v = request.values.get("q")
    return flask.render_template(v)


# CASE 6
@app.route("/case6")
def case6():
    v = request.get_json()
    return flask.render_template_string(v)


# CASE 7
@app.route("/case7")
def case7():
    v = request.json.get("q")
    return Response(v)


# CASE 8
@app.route("/case8")
def case8():
    v = request.data
    return flask.Response(v)


# CASE 9
@app.route("/case9")
def case9():
    v = request.get_data()
    return make_response(v)


# CASE 10
@app.route("/case10")
def case10():
    v = request.body
    return flask.make_response(v)


# CASE 11
@app.route("/case11")
def case11():
    v = request.headers.get("User-Agent")
    return Markup(v)


# CASE 12
@app.route("/case12")
def case12():
    v = request.cookies.get("q")
    return markupsafe.Markup(v)


# CASE 13
@app.route("/case13")
def case13():
    v = request.cookies["q"]
    return render(v)


# CASE 14
@app.route("/case14")
def case14():
    v = request.GET["q"]
    return django.shortcuts.render(v)


# CASE 15
@app.route("/case15")
def case15():
    v = request.POST["q"]
    return HttpResponse(v)


# CASE 16
@app.route("/case16")
def case16():
    v = request.COOKIES["q"]
    return django.http.HttpResponse(v)


# CASE 17
@app.route("/case17")
def case17():
    v = request.META["HTTP_USER_AGENT"]
    return HttpResponseBadRequest(v)


# CASE 18
@app.route("/case18")
def case18():
    v = request.query_params["q"]
    return HttpResponseNotFound(v)


# CASE 19
@app.route("/case19")
def case19():
    v = request.path_params["q"]
    return HttpResponseForbidden(v)


# CASE 20
@app.route("/case20")
def case20():
    v = request.stream
    return HttpResponseRedirect(v)


# CASE 21
@app.route("/case21")
def case21():
    v = input()
    return TemplateResponse(v)


# CASE 22
@app.route("/case22")
def case22():
    v = request.args.get("q")
    return Jinja2Templates.TemplateResponse(v)


# CASE 23
@app.route("/case23")
def case23():
    v = request.form.get("q")
    return templates.TemplateResponse(v)


# CASE 24
@app.route("/case24")
def case24():
    v = request.values.get("q")
    return HTMLResponse(v)


# CASE 25
@app.route("/case25")
def case25():
    v = request.json["q"]
    return fastapi.responses.HTMLResponse(v)


# CASE 26
@app.route("/case26")
def case26():
    v = request.args["q"]
    return PlainTextResponse(v)


# CASE 27
@app.route("/case27")
def case27():
    v = request.form["q"]
    return fastapi.responses.PlainTextResponse(v)


# CASE 28
@app.route("/case28")
def case28():
    v = request.headers.get("User-Agent")
    return CustomResponse(v)


# CASE 29
@app.route("/case29")
def case29():
    v = request.cookies.get("q")
    return CustomRender(v)


if __name__ == "__main__":
    app.run(debug=True)
