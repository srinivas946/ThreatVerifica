# Generated by Django 2.1.2 on 2018-12-13 05:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('check', '0003_virus_total_credits'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Ibm_API_Credits',
        ),
        migrations.DeleteModel(
            name='Virus_Total_Credits',
        ),
    ]
