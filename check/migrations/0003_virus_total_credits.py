# Generated by Django 2.1.2 on 2018-12-13 05:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('check', '0002_virus_total_hash_score'),
    ]

    operations = [
        migrations.CreateModel(
            name='Virus_Total_Credits',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('apikey', models.CharField(max_length=200)),
            ],
        ),
    ]
