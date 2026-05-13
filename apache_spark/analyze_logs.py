"""
Enhanced Spark Security Log Analysis with Elasticsearch
"""
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, avg, max, min, sum, when, desc

# Spark session with Elasticsearch configuration
spark = SparkSession.builder \
    .appName("SecurityAnalytics") \
    .master("local[*]") \
    .config("spark.jars", "file:///home/wind/cybersec-platform-saad/spark/elasticsearch-spark-30_2.12-8.11.0.jar") \
    .config("spark.es.nodes", "localhost") \
    .config("spark.es.port", "9200") \
    .config("spark.es.nodes.wan.only", "false") \
    .config("spark.es.nodes.discovery", "false") \
    .config("spark.es.index.auto.create", "true") \
    .config("spark.es.net.http.auth.user", "") \
    .config("spark.es.net.http.auth.pass", "") \
    .config("spark.es.resource.read", "security-logs") \
    .config("spark.es.read.metadata", "true") \
    .getOrCreate()

# Set log level to reduce noise
spark.sparkContext.setLogLevel("WARN")

print("=" * 60)
print("🔍 SECURITY LOG ANALYSIS FROM ELASTICSEARCH")
print("=" * 60)

try:
    # Read data from Elasticsearch
    print("\n📥 Reading data from Elasticsearch...")
    df = spark.read \
        .format("org.elasticsearch.spark.sql") \
        .option("es.resource", "security-logs") \
        .option("es.nodes.wan.only", "true") \
        .option("es.nodes.discovery", "false") \
        .load()


    # Register temp view for SQL queries
    df.createOrReplaceTempView("security_logs")

    print(f"\n✅ Total records loaded: {df.count()}")
    print("\n📊 Schema:")
    df.printSchema()

    print("\n📋 Sample data (first 5 rows):")
    df.show(5, truncate=False)

    # Analysis 1: User Activity Summary
    print("\n" + "=" * 60)
    print("📈 USER ACTIVITY SUMMARY")
    print("=" * 60)
    df.groupBy("user_id") \
      .agg(count("*").alias("total_actions"),
           avg("files_accessed").alias("avg_files"),
           max("files_accessed").alias("max_files"),
           min("files_accessed").alias("min_files")) \
      .orderBy(col("total_actions").desc()) \
      .show(10)

    # Analysis 2: Suspicious Location Analysis
    print("\n" + "=" * 60)
    print("🌍 SUSPICIOUS LOCATION ANALYSIS")
    print("=" * 60)
    if 'location' in df.columns:
        df.filter(col("location") != "Pakistan") \
          .groupBy("user_id", "location") \
          .agg(count("*").alias("access_count")) \
          .orderBy(col("access_count").desc()) \
          .show()
    else:
        print("Location column not found in data")

    # Analysis 3: Threat Score Analysis (if column exists)
    if 'threat_score' in df.columns:
        print("\n" + "=" * 60)
        print("⚠️  THREAT SCORE ANALYSIS")
        print("=" * 60)
        df.select("user_id", "action", "threat_score") \
          .filter(col("threat_score") > 5) \
          .orderBy(col("threat_score").desc()) \
          .show(10)

    # Analysis 4: Action Distribution
    print("\n" + "=" * 60)
    print("📊 ACTION DISTRIBUTION")
    print("=" * 60)
    df.groupBy("action") \
      .agg(count("*").alias("count")) \
      .orderBy(col("count").desc()) \
      .show()

    # Analysis 5: Device Analysis
    if 'device' in df.columns:
        print("\n" + "=" * 60)
        print("💻 DEVICE USAGE ANALYSIS")
        print("=" * 60)
        df.groupBy("device") \
          .agg(count("*").alias("usage_count"),
               avg("files_accessed").alias("avg_files")) \
          .orderBy(col("usage_count").desc()) \
          .show()

except Exception as e:
    print(f"\n❌ Error connecting to Elasticsearch: {e}")
    print("\n📝 Creating sample analysis with test data...")

    # Sample test data
    data = [
        ("ali", "login", 10, "Pakistan", "laptop", 2.0),
        ("ali", "download", 5000, "Russia", "unknown", 9.5),
        ("sara", "login", 20, "Pakistan", "mobile", 1.0),
        ("ahmed", "logout", 5, "Pakistan", "laptop", 1.0),
        ("fatima", "file_access", 100, "UAE", "laptop", 7.5),
        ("ali", "upload", 50, "Pakistan", "laptop", 3.0),
        ("sara", "download", 200, "China", "mobile", 8.0),
    ]

    df = spark.createDataFrame(data, ["user_id", "action", "files_accessed", "location", "device", "threat_score"])

    print("\n📋 Sample Data:")
    df.show()

    print("\n📈 User Activity:")
    df.groupBy("user_id") \
      .agg(count("*").alias("actions"),
           avg("files_accessed").alias("avg_files")) \
      .show()

    print("\n⚠️  High Threat Activities (score > 5):")
    df.filter(col("threat_score") > 5).show()

    print("\n🌍 Suspicious Activity (non-Pakistan):")
    df.filter(col("location") != "Pakistan").show()

print("\n" + "=" * 60)
print("✅ Analysis Complete!")
print("=" * 60)

# Keep Spark running for interactive exploration
print("\n💡 Spark session is still active. You can run more queries.")
print("Press Enter to stop Spark and exit...")
input()

spark.stop()
