import re
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
import requests


# 1. Настройки
BASE_URL = "https://qa-internship.avito.com"
REQUEST_TIMEOUT = 15

UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


# 2. Небольшие вспомогательные функции.
class SensitiveData(dict):
    """Скрывает секреты в представлении данных фикстуры в отчёте pytest."""

    def __repr__(self):
        hidden = {"password", "token", "accessToken"}
        return repr({key: "<hidden>" if key in hidden else value
                     for key, value in self.items()})


def api_request(method, path, token=None, json_body=None):
    """Отправляет запрос; ожидаемый HTTP-код проверяется отдельно в тесте.
    token=None означает отсутствие Authorization.
    """
    method = method.upper()
    headers = {"Accept": "application/json"}
    if method == "POST":
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        return requests.request(
            method,
            f"{BASE_URL}{path}",
            headers=headers,
            json=json_body,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as error:
        pytest.fail(
            f"{method} {path}: {type(error).__name__}; "
            f"таймаут запроса {REQUEST_TIMEOUT} с.",
            pytrace=False,
        )


def assert_status(response, expected_status, case_id):
    assert response.status_code == expected_status, (
        f"{case_id}: ожидался HTTP {expected_status}, "
        f"получен HTTP {response.status_code}"
    )

    if 400 <= expected_status < 600:
        path = urlsplit(response.url).path.rstrip("/")
        if path in ("/api/1/register", "/api/1/autorize"):
            return

        body = response_json(response, case_id)
        is_object = isinstance(body, dict)
        assert is_object, f"{case_id}: ожидался JSON-объект ошибки."

        if "status" not in body:
            return

        status_matches = str(body.get("status")) == str(response.status_code)
        assert status_matches, (
            f"{case_id}: поле status в JSON не совпадает "
            f"с HTTP {response.status_code}."
        )


def response_json(response, case_id):
    try:
        return response.json()
    except ValueError:
        pytest.fail(
            f"{case_id}: ответ HTTP {response.status_code} не содержит корректный JSON.",
            pytrace=False,
        )


def new_credentials():
    return SensitiveData(
        username=f"student_{uuid4().hex}",
        password=f"password_{uuid4().hex}",
    )


def register_user(credentials):
    response = api_request("POST", "/api/1/register", json_body=credentials)
    assert_status(response, 201, "Подготовка: регистрация пользователя")
    body = response_json(response, "Подготовка: регистрация пользователя")
    assert isinstance(body, dict), "Регистрация должна вернуть JSON-объект."
    assert body.get("id") not in (None, ""), "Регистрация не вернула id."
    assert body.get("username") == credentials["username"], (
        "Регистрация вернула другой username."
    )
    return SensitiveData(
        id=body["id"],
        username=credentials["username"],
        password=credentials["password"],
    )


def authorize_user(user):
    credentials = SensitiveData(username=user["username"], password=user["password"])
    response = api_request("POST", "/api/1/autorize", json_body=credentials)
    assert_status(response, 200, "Подготовка: авторизация пользователя")
    body = response_json(response, "Подготовка: авторизация пользователя")
    assert isinstance(body, dict), "Авторизация должна вернуть JSON-объект."
    assert isinstance(body.get("accessToken"), str) and body["accessToken"], (
        "Авторизация не вернула непустой строковый accessToken."
    )
    assert body.get("tokenType") == "Bearer", "Неожиданный tokenType."
    return SensitiveData(user, token=body["accessToken"])


def make_item_payload(seller_id):
    return {
        "sellerID": seller_id,
        "name": f"item_{uuid4().hex}",
        "price": 67,
        "statistics": {"likes": 52, "viewCount": 52, "contacts": 52},
    }


def remember_created_item(response, owner_token, created_items):
    """Сохраняет UUID из ответа своего POST /item до проверок assert """
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict) or not isinstance(body.get("status"), str):
        return None
    match = UUID_PATTERN.search(body["status"])
    if match is None:
        return None

    item_id = str(UUID(match.group(0)))
    if not any(item["id"] == item_id for item in created_items):
        created_items.append(SensitiveData(id=item_id, token=owner_token))
    return item_id


def tamper_jwt_signature(token):
    header, payload, signature = token.split(".")
    if not signature:
        raise ValueError("Для проверки нужна непустая подпись JWT.")
    first_char = "B" if signature[0] == "A" else "A"
    return f"{header}.{payload}.{first_char}{signature[1:]}"


def create_item(owner, created_items, payload=None):
    """Обычная функция: создаёт объявление и добавляет его в список для удаления."""
    data = payload
    if data is None:
        data = make_item_payload(owner["id"])
    response = api_request(
        "POST", "/api/1/item", token=owner["token"], json_body=data,
    )
    item_id = remember_created_item(response, owner["token"], created_items)
    assert_status(response, 200, "Подготовка: создание объявления")
    assert item_id is not None, "Создание не вернуло UUID в поле status."
    return {"id": item_id, "payload": data}


def get_seller_items(owner, case_id):
    """Получает список объявлений владельца с его токеном."""
    response = api_request(
        "GET", f"/api/1/{owner['id']}/item", token=owner["token"],
    )
    assert_status(response, 200, case_id)
    items = response_json(response, case_id)
    assert isinstance(items, list), f"{case_id}: ожидался массив объявлений."
    return items


def assert_item_data(owner, created_item, case_id):
    """Проверяет наличие объявления и его UUID, продавца, название и цену."""
    response = api_request(
        "GET", f"/api/1/item/{created_item['id']}", token=owner["token"],
    )
    assert_status(response, 200, case_id)
    body = response_json(response, case_id)
    assert isinstance(body, list), f"{case_id}: ожидался массив объявлений."
    assert len(body) == 1, f"{case_id}: ожидалось одно объявление."
    item = body[0]
    assert isinstance(item, dict), f"{case_id}: ожидался объект объявления."
    assert item.get("id") == created_item["id"], f"{case_id}: неверный UUID."
    assert item.get("sellerId") == owner["id"], f"{case_id}: неверный продавец."
    assert item.get("name") == created_item["payload"]["name"], f"{case_id}: название изменилось."
    assert item.get("price") == created_item["payload"]["price"], f"{case_id}: цена изменилась."


# 3. Фикстуры pytest
@pytest.fixture
def credentials():
    """Генерирует данные, но ещё не регистрирует пользователя."""
    return new_credentials()


@pytest.fixture
def registered_user(credentials):
    """Регистрирует пользователя с данными из фикстуры credentials."""
    return register_user(credentials)


@pytest.fixture
def authorized_user(registered_user):
    """Получает токен для пользователя из фикстуры registered_user."""
    return authorize_user(registered_user)


@pytest.fixture
def created_items():
    """Реестр объявлений только текущего теста; очистка работает и при падении."""
    items = []
    # До yield: подготовка. Список передаётся в тест.
    yield items

    # После yield: удаление объявлений, когда тест завершился.
    errors = []
    for item in reversed(items):
        try:
            response = requests.delete(
                f"{BASE_URL}/api/2/item/{item['id']}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {item['token']}",
                },
                timeout=REQUEST_TIMEOUT,
            )
            # В тестах удаления объект мог быть удалён основным запросом.
            if response.status_code not in (200, 404):
                errors.append(f"{item['id']}: HTTP {response.status_code}")
        except requests.RequestException as error:
            errors.append(f"{item['id']}: {type(error).__name__}")

    if errors:
        pytest.fail("Ошибки очистки объявлений: " + "; ".join(errors), pytrace=False)


# 4. Регистрация: API-01–API-03.
def test_api_01_register(credentials):
    """API-01: успешная регистрация нового пользователя."""
    register_user(credentials)



@pytest.mark.parametrize("missing_field", [
    pytest.param("username", id="API-02a"),
    pytest.param("password", id="API-02b"),
    pytest.param(None, id="API-02c-empty-json"),
])
def test_api_02_register_missing_field(credentials, missing_field):
    """API-02: регистрация без полей; None обозначает пустой JSON-объект."""
    payload = credentials.copy()

    if missing_field is None:
        payload = {}
    else:
        del payload[missing_field]

    response = api_request(
        "POST",
        "/api/1/register",
        json_body=payload,
    )
    assert_status(response, 400, "API-02")



def test_api_03_register_existing_user(registered_user):
    """API-03: повторная регистрация того же username."""
    user1 = registered_user

    user2 = SensitiveData(
        username=user1["username"],
        password=user1["password"],
    )

    response = api_request(
        "POST",
        "/api/1/register",
        json_body=user2,
    )

    assert_status(response, 409, "API-03")

# 5. Авторизация: API-04–API-06.
def test_api_04_authorize_registered_user(registered_user):
    """API-04: авторизация зарегистрированного пользователя."""
    authorize_user(registered_user)



def test_api_05_authorize_unknown_user(credentials):
    """API-05: авторизация без предварительной регистрации."""

    resonse = api_request(
        "POST", 
        "/api/1/autorize",
        token=None,
        json_body=credentials,
    )
    assert_status(resonse, 401, "API-05")


@pytest.mark.parametrize("missing_field", [
    pytest.param(None, id="API-06a-empty-json"),
    pytest.param("username", id="API-06b"),
    pytest.param("password", id="API-06c"),
])
def test_api_06_authorize_missing_field(registered_user, missing_field):
    """API-06: авторизация с неполными данными."""
    payload = SensitiveData(
        username=registered_user["username"],
        password=registered_user["password"],
    )

    if missing_field is None:
        payload = {}
    else:
        del payload[missing_field]

    response = api_request(
        "POST",
        "/api/1/autorize",
        json_body=payload,
    )
    assert_status(response, 400, "API-06")


# 6. Создание объявлений: API-07–API-09.
def test_api_07_create_item(authorized_user, created_items):
    """API-07: создание объявления с sellerID пользователя из токена."""
    created_item = create_item(authorized_user, created_items)
    payload = created_item["payload"]

    response = api_request(
        "GET",
        f"/api/1/item/{created_item['id']}",
        token=authorized_user["token"],
    )
    assert_status(response, 200, "API-07: получение созданного объявления")
    body = response_json(response, "API-07")

    assert isinstance(body, list), "API-07: GET должен вернуть массив."
    assert len(body) == 1, "API-07: ожидалось ровно одно объявление."

    item = body[0]
    assert isinstance(item, dict), "API-07: объявление должно быть JSON-объектом."
    assert item.get("id") == created_item["id"], "API-07: получено другое объявление."
    assert item.get("sellerId") == payload["sellerID"], "API-07: неверный продавец."
    assert item.get("name") == payload["name"], "API-07: название не совпадает."
    assert item.get("price") == payload["price"], "API-07: цена не совпадает."



def test_api_08_create_item_for_another_seller(authorized_user, created_items):
    """API-08: токен B и sellerID пользователя A."""
    user_b = authorized_user
    user_a = register_user(new_credentials())

    payload = make_item_payload(user_a["id"])
    response = api_request(
        "POST",
        "/api/1/item",
        token=user_b["token"],
        json_body=payload,
    )
    assert_status(response, 400, "API-08: создание объявления для другого продавца")



@pytest.mark.parametrize("missing_field", [
    pytest.param("name", id="API-09a"),
    pytest.param("price", id="API-09b"),
    pytest.param("statistics", id="API-09c"),
])
def test_api_09_create_item_missing_field(authorized_user, created_items, missing_field):
    """API-09: создание объявления без одного из полей."""
    payload = make_item_payload(authorized_user["id"])
    del payload[missing_field]

    response = api_request(
        "POST",
        "/api/1/item",
        token=authorized_user["token"],
        json_body=payload,
    )
    remember_created_item(response, authorized_user["token"], created_items)

    assert_status(response, 400, f"API-09: отсутствует {missing_field}")


# 7. Получение объявления: API-10–API-12.

def test_api_10_get_item(authorized_user, created_items):
    """API-10: получение одного объявления."""
    created_item = create_item(authorized_user, created_items)
    control_item = create_item(authorized_user, created_items)
    assert created_item["id"] != control_item["id"], "API-10: UUID двух объявлений совпали."

    response = api_request(
        "GET",
        f"/api/1/item/{created_item['id']}",
        token=authorized_user["token"],
    )
    assert_status(response, 200, "API-10")
    body = response_json(response, "API-10")
    assert isinstance(body, list), "API-10: GET должен вернуть массив."
    assert len(body) == 1, "API-10: ожидалось ровно одно объявление."

    item = body[0]
    payload = created_item["payload"]
    assert isinstance(item, dict), "API-10: объявление должно быть JSON-объектом."
    assert item.get("id") == created_item["id"], "API-10: получено другое объявление."
    assert item.get("sellerId") == payload["sellerID"], "API-10: неверный продавец."
    assert item.get("name") == payload["name"], "API-10: название не совпадает."
    assert item.get("price") == payload["price"], "API-10: цена не совпадает."


def test_api_11_get_missing_item(authorized_user):
    """API-11: получение отсутствующего объявления по корректному UUID."""
    missing_item_id = str(uuid4())
    response = api_request(
        "GET",
        f"/api/1/item/{missing_item_id}",
        token=authorized_user["token"],
    )
    assert_status(response, 404, "API-11")


def test_api_12_get_item_invalid_uuid(authorized_user):
    """API-12: получение объявления по not-a-uuid."""
    response = api_request(
        "GET",
        "/api/1/item/not-a-uuid",
        token=authorized_user["token"],
    )
    assert_status(response, 400, "API-12")


# 8. Объявления продавца: API-13–API-14.
def test_api_13_get_seller_items(authorized_user, created_items):
    """API-13: получение двух объявлений одного пользователя."""
    first_item = create_item(authorized_user, created_items)
    second_item = create_item(authorized_user, created_items)
    assert first_item["id"] != second_item["id"], "API-13: UUID двух объявлений совпали."

    response = api_request(
        "GET",
        f"/api/1/{authorized_user['id']}/item",
        token=authorized_user["token"],
    )
    assert_status(response, 200, "API-13")
    body = response_json(response, "API-13")
    assert isinstance(body, list), "API-13: ожидался массив объявлений."
    assert len(body) == 2, "API-13: ожидалось ровно два объявления."

    returned_ids = []
    for item in body:
        assert isinstance(item, dict), "API-13: объявление должно быть JSON-объектом."
        returned_ids.append(item.get("id"))
        assert item.get("sellerId") == authorized_user["id"], "API-13: неверный продавец."

    assert first_item["id"] in returned_ids, "API-13: первое объявление не найдено."
    assert second_item["id"] in returned_ids, "API-13: второе объявление не найдено."

def test_api_14_get_seller_items_invalid_id(authorized_user):
    """API-14: нечисловой sellerID."""
    response = api_request(
        "GET",
        "/api/1/not-a-number/item",
        token=authorized_user["token"],
    )
    assert_status(response, 400, "API-14")


# 9. Статистика v1: API-15–API-17.
def test_api_15_get_statistics_v1(authorized_user, created_items):
    """API-15: статистика собственного существующего объявления через v1."""
    item = create_item(authorized_user, created_items)

    response = api_request(
        "GET",
        f"/api/1/statistic/{item['id']}",
        token=authorized_user["token"],
    )
    assert_status(response, 200, "API-15")
    body = response_json(response, "API-15")
    assert isinstance(body, list), "API-15: ожидался массив статистики."
    assert len(body) > 0, "API-15: статистика созданного объявления отсутствует."


def test_api_16_get_missing_statistics_v1(authorized_user):
    """API-16: отсутствующее объявление, версия статистики v1."""
    missing_item_id = str(uuid4())
    response = api_request(
        "GET",
        f"/api/1/statistic/{missing_item_id}",
        token=authorized_user["token"],
    )
    assert_status(response, 404, "API-16")


def test_api_17_get_statistics_v1_invalid_uuid(authorized_user):
    """API-17: неправильный формат UUID для статистики v1."""
    response = api_request(
        "GET",
        "/api/1/statistic/not-a-uuid",
        token=authorized_user["token"],
    )
    assert_status(response, 400, "API-17")


# 10. Статистика v2: API-18–API-20.
def test_api_18_get_statistics_v2(authorized_user, created_items):
    """API-18: статистика собственного существующего объявления через v2."""
    payload = make_item_payload(authorized_user["id"])
    payload["statistics"] = {"likes": 21, "viewCount": 11, "contacts": 43}
    item = create_item(authorized_user, created_items, payload=payload)

    response = api_request(
        "GET",
        f"/api/2/statistic/{item['id']}",
        token=authorized_user["token"],
    )
    assert_status(response, 200, "API-18")
    body = response_json(response, "API-18")
    assert body is not None, "API-18: вместо данных статистики получен null."


def test_api_19_get_missing_statistics_v2(authorized_user):
    """API-19: отсутствующее объявление, версия статистики v2."""
    missing_item_id = str(uuid4())
    response = api_request(
        "GET",
        f"/api/2/statistic/{missing_item_id}",
        token=authorized_user["token"],
    )
    assert_status(response, 404, "API-19")


def test_api_20_get_statistics_v2_invalid_uuid(authorized_user):
    """API-20: неправильный формат UUID для статистики v2."""
    response = api_request(
        "GET",
        "/api/2/statistic/not-a-uuid",
        token=authorized_user["token"],
    )
    assert_status(response, 404, "API-20")


# 11. Удаление: API-21–API-23.
def test_api_21_delete_item(authorized_user, created_items):
    """API-21: удаление собственного объявления и сохранность контрольного."""
    item = create_item(authorized_user, created_items)
    control_item = create_item(authorized_user, created_items)
    assert item["id"] != control_item["id"], "API-21: UUID двух объявлений совпали."
    assert_item_data(authorized_user, item, "API-21: целевое объявление до удаления")
    assert_item_data(authorized_user, control_item, "API-21: контроль до удаления")

    response = api_request(
        "DELETE", f"/api/2/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 200, "API-21: удаление")

    deleted_response = api_request(
        "GET", f"/api/1/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(deleted_response, 404, "API-21: объявление после удаления")

    remaining_items = get_seller_items(authorized_user, "API-21: список после удаления")
    assert len(remaining_items) == 1, "API-21: должно остаться одно контрольное объявление."
    assert isinstance(remaining_items[0], dict), "API-21: ожидался объект объявления."
    assert remaining_items[0].get("id") == control_item["id"], "API-21: в списке осталось неверное объявление."
    assert_item_data(authorized_user, control_item, "API-21: контроль после удаления")


def test_api_22_delete_missing_item(authorized_user, created_items):
    """API-22: повторное удаление своего уже удалённого объявления."""
    item = create_item(authorized_user, created_items)
    control_item = create_item(authorized_user, created_items)
    assert item["id"] != control_item["id"], "API-22: UUID двух объявлений совпали."

    first_delete = api_request(
        "DELETE", f"/api/2/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(first_delete, 200, "API-22: подготовка отсутствующего объявления")
    missing_response = api_request(
        "GET", f"/api/1/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(missing_response, 404, "API-22: подтверждение отсутствия")

    response = api_request(
        "DELETE", f"/api/2/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 404, "API-22: повторное удаление")
    assert_item_data(authorized_user, control_item, "API-22: контрольное объявление")


def test_api_23_delete_item_invalid_uuid(authorized_user, created_items):
    """API-23: удаление по not-a-uuid и сохранность контрольного объявления."""
    control_item = create_item(authorized_user, created_items)
    response = api_request(
        "DELETE", "/api/2/item/not-a-uuid", token=authorized_user["token"],
    )
    assert_status(response, 400, "API-23")
    assert_item_data(authorized_user, control_item, "API-23: контрольное объявление")


# 12. Без Authorization: API-24–API-29. В основном запросе token=None.
def test_api_24_create_item_without_token(authorized_user, created_items):
    """API-24: попытка создания объявления зарегистрированным пользователем без токена."""
    payload = make_item_payload(authorized_user["id"])
    response = api_request(
        "POST", "/api/1/item", token=None, json_body=payload,
    )
    saved_id = remember_created_item(response, authorized_user["token"], created_items)

    items = get_seller_items(authorized_user, "API-24: список после POST")
    # Если запись всё же появилась, учитываем её для очистки до assert.
    for item in items:
        assert isinstance(item, dict), "API-24: ожидался объект объявления."
        if item.get("name") == payload["name"] and item.get("id") != saved_id:
            created_items.append(SensitiveData(id=item["id"], token=authorized_user["token"]))

    assert_status(response, 401, "API-24")
    assert items == [], "API-24: после POST без Authorization список объявлений не пуст."


def test_api_25_get_item_without_token(authorized_user, created_items):
    """API-25: получение существующего объявления без токена."""
    item = create_item(authorized_user, created_items)
    response = api_request("GET", f"/api/1/item/{item['id']}", token=None)
    assert_status(response, 401, "API-25")
    name_leaked = item["payload"]["name"] in response.text
    assert not name_leaked, "API-25: в ответе раскрыто название объявления."


def test_api_26_get_seller_items_without_token(authorized_user, created_items):
    """API-26: получение непустого списка продавца без токена."""
    item = create_item(authorized_user, created_items)
    response = api_request("GET", f"/api/1/{authorized_user['id']}/item", token=None)
    assert_status(response, 401, "API-26")
    name_leaked = item["payload"]["name"] in response.text
    assert not name_leaked, "API-26: в ответе раскрыто название объявления."


def test_api_27_get_statistics_v1_without_token(authorized_user, created_items):
    """API-27: статистика v1 существующего объявления без токена."""
    item = create_item(authorized_user, created_items)
    response = api_request("GET", f"/api/1/statistic/{item['id']}", token=None)
    assert_status(response, 401, "API-27")


def test_api_28_get_statistics_v2_without_token(authorized_user, created_items):
    """API-28: статистика v2 существующего объявления без токена."""
    item = create_item(authorized_user, created_items)
    response = api_request("GET", f"/api/2/statistic/{item['id']}", token=None)
    assert_status(response, 401, "API-28")


def test_api_29_delete_item_without_token(authorized_user, created_items):
    """API-29: удаление собственного тестового объявления без токена."""
    item = create_item(authorized_user, created_items)
    assert_item_data(authorized_user, item, "API-29: объявление до запроса")
    response = api_request("DELETE", f"/api/2/item/{item['id']}", token=None)
    assert_status(response, 401, "API-29")
    assert_item_data(authorized_user, item, "API-29: объявление после запроса")

    remaining_items = get_seller_items(authorized_user, "API-29: список после запроса")
    assert len(remaining_items) == 1, "API-29: объявление исчезло из списка."
    assert isinstance(remaining_items[0], dict), "API-29: ожидался объект объявления."
    assert remaining_items[0].get("id") == item["id"], "API-29: объявление отсутствует в списке."


# 13. Безопасность: API-30.
def test_api_30_invalid_jwt_signature(authorized_user, created_items):
    """API-30: отказ при неверной подписи JWT и контроль исходного токена."""
    item = create_item(authorized_user, created_items)
    assert_item_data(authorized_user, item, "API-30: исходный токен до проверки")

    try:
        tampered = SensitiveData(token=tamper_jwt_signature(authorized_user["token"]))
    except ValueError:
        pytest.fail(
            "API-30: нужен JWT формата header.payload.signature с непустой подписью.",
            pytrace=False,
        )

    response = api_request(
        "GET", f"/api/1/item/{item['id']}", token=tampered["token"],
    )
    used_tampered_token = (
        response.request.headers.get("Authorization") == f"Bearer {tampered['token']}"
    )
    assert used_tampered_token, "API-30: в основном запросе не передан подготовленный изменённый JWT."

    assert_item_data(authorized_user, item, "API-30: исходный токен после проверки")
    assert_status(response, 401, "API-30: неверная подпись JWT")
    name_leaked = item["payload"]["name"] in response.text
    assert not name_leaked, "API-30: с неверной подписью раскрыто название объявления."


# 14. Статистика после удаления объявления: API-31–API-32.
def test_api_31_get_statistics_v1_after_deletion(authorized_user, created_items):
    """API-31: статистика v1 недоступна после удаления объявления."""
    item = create_item(authorized_user, created_items)
    assert_item_data(authorized_user, item, "API-31: объявление до удаления")
    response = api_request(
        "GET", f"/api/1/statistic/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 200, "API-31: статистика до удаления")

    response = api_request(
        "DELETE", f"/api/2/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 200, "API-31: удаление объявления")
    response = api_request(
        "GET", f"/api/1/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 404, "API-31: подтверждение удаления")

    response = api_request(
        "GET", f"/api/1/statistic/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 404, "API-31: статистика после удаления")


def test_api_32_get_statistics_v2_after_deletion(authorized_user, created_items):
    """API-32: статистика v2 недоступна после удаления объявления."""
    item = create_item(authorized_user, created_items)
    assert_item_data(authorized_user, item, "API-32: объявление до удаления")
    response = api_request(
        "GET", f"/api/2/statistic/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 200, "API-32: статистика до удаления")

    response = api_request(
        "DELETE", f"/api/2/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 200, "API-32: удаление объявления")
    response = api_request(
        "GET", f"/api/1/item/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 404, "API-32: подтверждение удаления")

    response = api_request(
        "GET", f"/api/2/statistic/{item['id']}", token=authorized_user["token"],
    )
    assert_status(response, 404, "API-32: статистика после удаления")

