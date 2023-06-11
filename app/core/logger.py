from loguru import logger

logger.add("file_1.log", rotation="1 GB", serialize=True)

# context_logger = logger.bind(ip="192.168.0.1", user="someone")
# context_logger.warning("Contextualize your logger easily")
# context_logger.bind(user="someone_else").info("Inline binding of extra attribute")
# context_logger.error("Use kwargs to add context during formatting: {user}", user="anybody",
#                      user_agents=request.headers.get("user-agents"), ip=request.client.host)
